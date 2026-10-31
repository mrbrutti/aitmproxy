#!/usr/bin/env python3
# e2e: tier=T1 surface=web
"""Hard contract guard for what the web UI's /bus push adoption rests on (AC24).

Spec: docs/superpowers/specs/2026-10-30-web-ui-bus-push-design.md (wire-facts
table, D3, D6, D7). The UI now subscribes on every connection and treats a flow
push as a TRIGGER (refetch via flow.detail, never apply the sparse summary), and
it drops its own polling echo from the Activity panel by inferring own-ness from
`origin` + command because the bridge labels no connection. Each of those client
decisions depends on a server fact this suite pins against a REAL core over the
REAL /bus bridge, as the agent token (the `aitm web --token` value):

  1. flow.subscribe {} returns an integer sub_id            (server.rs subscribe)
  2. a flow push summary is exactly {id, kind, method, authority, path, status}
     with kind "http"                                        (server.rs flow_summary)
  3. flow.detail {id, body:"none"} returns kind "http" with request, client_conn,
     meta, and its `id` is the requested one                 (detail.rs detail)
  4. the UI's own flow.list is audited and pushed back as a notifications/aitm/agent
     line {at:int, origin:"mcp", client_label:null, command, args:str, result:"ok"}
                                                   (server.rs record_audit, audit.rs)
  4b. the flow.detail audit line's args parse back to exactly {id, body:"none"}:
     the UI's body-aware noise rule reads `body` off the echoed args
                                              (server.rs redact_args, redact.rs)
  5. a successful flow.subscribe is NOT audited             (server.rs call_tool)

Every check is hard (no skip). The two sibling suites in this directory are left
as they are (spec non-goal); this one sits beside them.
"""

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.proxyutil import via_proxy  # noqa: E402
from aitm_e2e.upstream import Upstream  # noqa: E402
from aitm_e2e.ws import WsBusClient  # noqa: E402

FLOW = "notifications/aitm/flow"
AGENT = "notifications/aitm/agent"
# The HTTP summary the server renders in `flow_summary` (crates/aitm-mcp/src/server.rs).
SUMMARY_KEYS = {"id", "kind", "method", "authority", "path", "status"}
PATH_TAG = "/echo?x=push-contract"
PUSH_WAIT_S = 8.0


def is_int(v) -> bool:
    """A JSON integer as Python parses it: int, and not the bool subclass."""
    return isinstance(v, int) and not isinstance(v, bool)


def params_of(ws, method: str) -> list[dict]:
    """The params of every stashed notification whose method is `method`."""
    return [m.get("params") or {} for m in ws.notifications if m.get("method") == method]


def collect_until(ws, found, timeout: float):
    """Drain pushed lines in short slices until `found()` returns a truthy value or
    the deadline passes. `rpc()` already stashes any line that is not its reply, so
    `ws.notifications` is the one place every pushed line ends up."""
    deadline = time.time() + timeout
    hit = found()
    while not hit and time.time() < deadline:
        ws.drain_notifications(timeout=0.5)
        hit = found()
    return hit


def main() -> int:
    up = Upstream().start()
    core = None
    ws = None
    try:
        section("boot aitm web + upstream (upstream in scope)")
        cfg = CoreConfig(proxy_port=free_port(), browser_proxy_port=free_port(),
                         scope_entries=[up.authority, "127.0.0.1"])
        core = Aitm.web(cfg)
        ok(f"aitm web on :{core.web_port}, proxy :{cfg.proxy_port}, upstream {up.base}")
        # The only client of this core is this one /bus connection: no browser is
        # opened (--no-open) and the harness makes no bus calls of its own. So
        # every audit line pushed here is for a call THIS suite made.
        ws = WsBusClient.web_agent(core)

        section("1. flow.subscribe {} over /bus returns an integer sub_id")
        # A refusal raises ToolError, which the __main__ guard turns into a FAIL.
        sub = ws.call("flow.subscribe", {})
        check(isinstance(sub, dict) and is_int(sub.get("sub_id")),
              f"flow.subscribe returned a dict with an integer sub_id: {sub!r}")

        section("2. real proxied traffic -> a notifications/aitm/flow whose summary is sparse")
        resp = via_proxy(cfg.proxy_port, "GET", f"{up.base}{PATH_TAG}")
        check(resp.status == 200, f"traffic through the proxy returned {resp.status}")

        def my_flow_line():
            # Tie the push to this suite's own request (authority + path), the way
            # tests/e2e/proto/test_http2_multiplex.py selects its pushed flows.
            for p in params_of(ws, FLOW):
                s = p.get("summary") or {}
                if s.get("authority") == up.authority and str(s.get("path", "")).startswith("/echo"):
                    return p
            return None

        line = collect_until(ws, my_flow_line, PUSH_WAIT_S)
        seen = [(p.get("event"), (p.get("summary") or {}).get("authority")) for p in params_of(ws, FLOW)]
        check(line is not None,
              f"a flow push for {up.authority}{PATH_TAG} arrived within {PUSH_WAIT_S:.0f}s "
              f"(flow lines seen: {seen})")
        summary = line.get("summary")
        check(isinstance(summary, dict) and set(summary.keys()) == SUMMARY_KEYS,
              f"push summary has exactly the keys {sorted(SUMMARY_KEYS)}: "
              f"{sorted(summary.keys()) if isinstance(summary, dict) else summary!r}")
        check(summary.get("kind") == "http",
              f"push summary kind is 'http' (the UI's toSummary maps only 'websocket'; "
              f"got {summary.get('kind')!r})")
        fid = line.get("id")
        check(isinstance(fid, str) and fid != "" and fid == summary.get("id"),
              f"push carries the flow id at top level and in the summary: {fid!r}")

        section("3. flow.detail {id, body:'none'} for that id is the rich row the UI refetches")
        detail = ws.call("flow.detail", {"id": fid, "body": "none"})
        check(isinstance(detail, dict) and detail.get("kind") == "http",
              f"flow.detail kind is 'http' (got {detail.get('kind') if isinstance(detail, dict) else detail!r})")
        for key in ("request", "client_conn", "meta"):
            check(isinstance(detail, dict) and key in detail, f"flow.detail carries `{key}`")
        # The UI discards a reply that does not name the requested id (spec D3, after
        # review round 1), so the row must carry it: `detail` always inserts `id` =
        # the looked-up flow's id (crates/aitm-plugins/src/detail.rs:152) and the
        # lookup is by the requested `id` (detail.rs:112-117), so the two are equal.
        check(isinstance(detail, dict) and detail.get("id") == fid,
              f"flow.detail reply names the requested flow id {fid!r} "
              f"(got {detail.get('id') if isinstance(detail, dict) else detail!r})")

        section("4. the UI's own flow.list comes back as an audit line in the server shape")
        ws.call("flow.list")

        def flow_list_lines():
            # Filter by command so the flow.detail line from step 3 (and any flow.list
            # line a flow.subscribe audit would have produced) is never mistaken for it.
            mine = [p for p in params_of(ws, AGENT) if p.get("command") == "flow.list"]
            return mine or None

        mine = collect_until(ws, flow_list_lines, PUSH_WAIT_S)
        check(mine is not None,
              f"an audit line for flow.list was pushed to the subscriber within {PUSH_WAIT_S:.0f}s "
              f"(agent commands seen: {sorted({str(p.get('command')) for p in params_of(ws, AGENT)})})")
        # This suite made exactly one flow.list call on the only connection to this
        # core, so exactly one such line proves the one we assert on is ours.
        check(len(mine) == 1, f"exactly one flow.list audit line (got {len(mine)}): it is this suite's call")
        a = mine[0]
        check(is_int(a.get("at")), f"agent line `at` is an integer (epoch ms), got {a.get('at')!r}")
        check(a.get("origin") == "mcp",
              f"agent line origin is 'mcp' (the --token value is the agent token), got {a.get('origin')!r}")
        # Pins the fact the UI's noise rule rests on: the /bus bridge mints its one
        # ConnCtx with `client_label: None` (crates/aitm/src/web/bridge.rs:251-257),
        # so bridge audit lines are unlabelled and the UI's own lines carry
        # `client_label: null`, never "aitm-web". The rule (`isUiPollNoise`,
        # apps/web/src/bus/noise.ts) therefore infers own-ness from `origin` +
        # command (spec D7, R2). If a server change starts labelling bridge
        # connections this check fails on purpose: revisit D7 then. The follow-up
        # is a SERVER-assigned connection id on audit lines, NOT trusting a
        # client-declared label (initialize.clientInfo.name is forgeable; spec D7
        # third amendment).
        check("client_label" in a and a["client_label"] is None,
              f"agent line client_label is null over /bus (got {a.get('client_label', '<absent>')!r})")
        check(a.get("command") == "flow.list", f"agent line command is 'flow.list', got {a.get('command')!r}")
        check(isinstance(a.get("args"), str),
              f"agent line args is a (redacted JSON) string, got {type(a.get('args')).__name__}")
        check(a.get("result") == "ok", f"agent line result is 'ok', got {a.get('result')!r}")

        section("4b. the flow.detail audit line carries the call's exact args, body:'none' included")
        # The UI drops its own flow.detail echo only in the poll's exact shape, args.body
        # == 'none' (apps/web/src/bus/noise.ts isPollDetail; spec D7), so that rule rests
        # on two server facts pinned here: the audited `args` is the call's arguments
        # object, redacted by key and content and rendered as JSON (crates/aitm-mcp/src/
        # server.rs redact_args), and neither `id` nor `body` is a secret key
        # (crates/aitm-core/src/redact.rs SECRET_KEY_NEEDLES), so both survive verbatim.
        # Step 3 made exactly one flow.detail call on the only connection to this core.

        def flow_detail_lines():
            mine = [p for p in params_of(ws, AGENT) if p.get("command") == "flow.detail"]
            return mine or None

        details = collect_until(ws, flow_detail_lines, PUSH_WAIT_S)
        check(details is not None,
              f"an audit line for flow.detail was pushed to the subscriber within {PUSH_WAIT_S:.0f}s "
              f"(agent commands seen: {sorted({str(p.get('command')) for p in params_of(ws, AGENT)})})")
        check(len(details) == 1, f"exactly one flow.detail audit line (got {len(details)}): it is step 3's call")
        d_args = details[0].get("args")
        check(isinstance(d_args, str), f"flow.detail agent line args is a string, got {type(d_args).__name__}")
        try:
            parsed = json.loads(d_args) if isinstance(d_args, str) else None
        except ValueError:
            parsed = None
        check(parsed == {"id": fid, "body": "none"},
              f"flow.detail args round-trip to exactly {{'id': {fid!r}, 'body': 'none'}} (got {parsed!r})")

        section("5. a successful flow.subscribe is not audited")
        # Any such line would have been pushed at subscribe time, long before now; a
        # short final drain catches stragglers so the scan is over everything sent.
        ws.drain_notifications(timeout=1.0)
        agent_lines = params_of(ws, AGENT)
        subscribe_lines = [p for p in agent_lines if p.get("command") == "flow.subscribe"]
        check(len(agent_lines) >= 1, f"the scan covers {len(agent_lines)} agent line(s), so it is not vacuous")
        check(not subscribe_lines,
              f"no agent line has command 'flow.subscribe' (commands seen: "
              f"{sorted({str(p.get('command')) for p in agent_lines})})")
        ok("web UI /bus push contract holds against the real core")
    finally:
        if ws:
            ws.close()
        if core:
            core.stop()
        up.stop()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
