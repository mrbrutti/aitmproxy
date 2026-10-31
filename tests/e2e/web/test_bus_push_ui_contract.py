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

Sections 6 and 7 pin the server-assigned connection id (spec:
docs/superpowers/specs/2026-10-30-bus-audit-connection-id-design.md, AC20, D1).
The id is opaque: only equality and "a str of 1 to 64 bytes" are asserted, never
its rendering. `client_label` stays null on every /bus line (the pin in 4 holds):
the bridge still does not copy clientInfo.name.

  6. `initialize` answers a top-level connection_id (a str of 1 to 64 bytes), a
     repeated initialize returns the same one, and every flow.list audit line of
     this connection carries it, with client_label null
                                (server.rs McpServer::connection_id, record_audit)
  7. a second /bus connection gets a different id; its proxy.status line reaches
     the first connection's stream with origin "mcp" and ITS id; re-initializing
     as clientInfo.name "aitm-web" changes neither the id nor the null label

Every check is hard (no skip). The two sibling suites in this directory are left
as they are (spec non-goal); this one sits beside them.
"""

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section  # noqa: E402
from aitm_e2e.bus import PROTOCOL_VERSION  # noqa: E402
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


def audit_lines(ws, command: str) -> list[dict]:
    """The params of every stashed audit line for `command`, in arrival order."""
    return [p for p in params_of(ws, AGENT) if p.get("command") == command]


def main() -> int:
    up = Upstream().start()
    core = None
    ws = None
    ws2 = None
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

        section("6. the connection's server-assigned id is stable and rides every audit line")
        # `WsBusClient.connect()` already initialized once; these are two repeats on
        # the same socket. `initialize` is not a tools/call, so it is never audited
        # and the line counts the earlier sections asserted are untouched.
        first = ws.initialize()
        again = ws.initialize()
        cid = first.get("connection_id")
        check(isinstance(cid, str) and 1 <= len(cid.encode("utf-8")) <= 64,
              f"initialize result carries connection_id as a str of 1 to 64 bytes "
              f"(got {cid!r}; result keys {sorted(first)})")
        check(again.get("connection_id") == cid,
              f"a repeated initialize returns the same connection_id "
              f"(got {again.get('connection_id')!r}, first was {cid!r})")
        ws.call("flow.list")

        def two_flow_lists():
            # Section 4's call plus the one above: at least two flow.list lines.
            got = audit_lines(ws, "flow.list")
            return got if len(got) >= 2 else None

        lists = collect_until(ws, two_flow_lists, PUSH_WAIT_S)
        check(lists is not None,
              f"at least two flow.list audit lines arrived within {PUSH_WAIT_S:.0f}s "
              f"(got {len(audit_lines(ws, 'flow.list'))})")
        check(all(p.get("connection_id") == cid for p in lists),
              f"every flow.list audit line ({len(lists)}) carries this connection's id {cid!r} "
              f"(got {[p.get('connection_id') for p in lists]!r})")
        check(all("client_label" in p and p["client_label"] is None for p in lists),
              f"every flow.list audit line still has client_label null "
              f"(got {[p.get('client_label', '<absent>') for p in lists]!r})")

        section("7. a second connection has its own id; re-initializing as 'aitm-web' changes nothing")
        ws2 = WsBusClient.web_agent(core)
        cid2 = ws2.initialize().get("connection_id")
        check(isinstance(cid2, str) and cid2 != cid,
              f"the second connection's connection_id is a str different from the first's "
              f"(got {cid2!r}, first {cid!r})")
        # ws2 never subscribed, so it receives no push; ws (subscribed on the same
        # server) must receive ws2's audit line. Both are agent-token links, so the
        # line's origin is 'mcp' and it is visible to ws. Nothing else called
        # proxy.status on this core, so exactly one such line is ws2's.
        ws2.call("proxy.status")

        def status_lines():
            return audit_lines(ws, "proxy.status") or None

        got = collect_until(ws, status_lines, PUSH_WAIT_S)
        check(got is not None,
              f"the first connection's stream received an audit line for the second "
              f"connection's proxy.status within {PUSH_WAIT_S:.0f}s "
              f"(agent commands seen: {sorted({str(p.get('command')) for p in params_of(ws, AGENT)})})")
        ws.drain_notifications(timeout=1.0)  # stragglers, so 'exactly one' is over everything sent
        got = audit_lines(ws, "proxy.status")
        check(len(got) == 1, f"exactly one proxy.status audit line on the first stream (got {len(got)})")
        check(got[0].get("origin") == "mcp",
              f"the second connection's line has origin 'mcp' (got {got[0].get('origin')!r})")
        check(got[0].get("connection_id") == cid2,
              f"the second connection's line carries ITS id {cid2!r}, not the first's "
              f"(got {got[0].get('connection_id')!r})")

        # The UI re-initializes as 'aitm-web' on reconnect; a client-declared name
        # must not move the server-assigned id nor give the bridge a label (D1, D2).
        renamed = ws.rpc("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "aitm-web", "version": "0"},
        })
        check(renamed.get("connection_id") == cid,
              f"re-initialize with clientInfo.name 'aitm-web' returns the same connection_id "
              f"(got {renamed.get('connection_id')!r}, expected {cid!r})")
        before = len(audit_lines(ws, "flow.list"))
        ws.call("flow.list")

        def one_more_flow_list():
            got = audit_lines(ws, "flow.list")
            return got if len(got) > before else None

        after = collect_until(ws, one_more_flow_list, PUSH_WAIT_S)
        check(after is not None,
              f"a flow.list audit line after the re-initialize arrived within {PUSH_WAIT_S:.0f}s "
              f"(had {before}, now {len(audit_lines(ws, 'flow.list'))})")
        last = after[-1]
        check(last.get("connection_id") == cid,
              f"the flow.list line after the re-initialize still carries id {cid!r} "
              f"(got {last.get('connection_id')!r})")
        check("client_label" in last and last["client_label"] is None,
              f"the flow.list line after the re-initialize still has client_label null "
              f"(got {last.get('client_label', '<absent>')!r}): clientInfo.name is never copied")
        ok("web UI /bus push contract holds against the real core")
    finally:
        if ws:
            ws.close()
        if ws2:
            ws2.close()
        if core:
            core.stop()
        up.stop()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
