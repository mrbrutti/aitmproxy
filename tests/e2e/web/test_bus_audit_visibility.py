#!/usr/bin/env python3
# e2e: tier=T1 surface=web
"""The audit stream's trust boundary over the REAL /bus bridge (AC21).

Spec: docs/superpowers/specs/2026-10-30-bus-audit-connection-id-design.md (D3, D4).
An agent-role connection must not read the trusted principal's audit lines, on
push or on pull, and `agent.status.actions_last_minute` counts only what the
asker may see. This boots a REAL `aitm web`, opens an AGENT bridge A (the
`--token` value) and an OPERATOR bridge O (the fresh bridge token `aitm web`
prints on startup), subscribes both with `flow.subscribe {}`, then makes exactly
these audited calls, in this order, on a fresh core (the ring after each call;
an entry is recorded when its call returns, so a call never counts itself):

  # call                              result                                    ring
  1 O proxy.status                    line on O's stream, origin "operator";      1
                                      never on A's stream
  2 A proxy.status (barrier)          line on A's and on O's stream, "mcp"        2
  3 A agent.activity                  1 entry: proxy.status, origin "mcp"         3
  4 O agent.activity                  3 entries, origins operator, mcp, mcp       4
  5 A agent.status {exclude_self}     actions_last_minute == 0                    5
  6 A agent.status {}                 actions_last_minute == 3                    6
  7 O agent.status {}                 actions_last_minute == 6                    7

Step 7 reads 6, not 5: the operator's own step-4 `agent.activity` is audited too,
so six audited calls precede it (O proxy.status, A proxy.status, A activity, O
activity, A status with exclude_self, A status). A count other than 6 is a FAIL,
never a number to adjust.

Barrier: the server fans a line out after the call returns, so a line's absence
from A's stream proves nothing until a LATER line of A's own (its step-2
`proxy.status`) has arrived. "Never on A's stream" is therefore asserted only
after that barrier, and once more over the whole run at the end.

Every check is hard (no skip). Needs nothing but the `aitm` binary: AITM_BIN
overrides target/debug/aitm (a baseline binary shows this red).
"""

import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.ws import WsBusClient  # noqa: E402

AGENT = "notifications/aitm/agent"
PUSH_WAIT_S = 8.0


def operator_bridge_token(core, timeout=10.0):
    """`aitm web` prints a fresh operator BRIDGE token on startup
    (`web UI (operator): http://.../#t=<tok>&expect=operator`). Parse it from the
    core's own captured output. Copied from tests/e2e/web/test_web_intercept.py."""
    pat = re.compile(r"t=([^&\s]+)&expect=operator")
    deadline = time.time() + timeout
    while time.time() < deadline:
        for text in (core.stdout_text(), core.stderr_text()):
            m = pat.search(text or "")
            if m:
                return m.group(1)
        time.sleep(0.2)
    return None


def redact_tokens(text: str) -> str:
    """Output safe to print in a failure: every `t=<token>` value is masked."""
    return re.sub(r"t=[^&\s]+", "t=<redacted>", text)


def lines_of(ws) -> list[dict]:
    """The params of every audit line stashed on this connection's stream, in the
    order they arrived. `rpc()` stashes any line that is not its reply, so
    `ws.notifications` is the one place every pushed line ends up."""
    return [m.get("params") or {} for m in ws.notifications if m.get("method") == AGENT]


def wait_lines(ws, pred, timeout: float = PUSH_WAIT_S) -> list[dict]:
    """Drain pushed lines in short slices until at least one stashed audit line
    satisfies `pred`, or the deadline passes. Returns every match (possibly none)."""
    deadline = time.time() + timeout
    while True:
        hits = [p for p in lines_of(ws) if pred(p)]
        if hits or time.time() >= deadline:
            return hits
        ws.drain_notifications(timeout=0.5)


def is_call(command: str, origin: str):
    return lambda p: p.get("command") == command and p.get("origin") == origin


def brief_lines(ws) -> list[tuple]:
    """(command, origin) of every audit line on the stream, for failure messages."""
    return [(p.get("command"), p.get("origin")) for p in lines_of(ws)]


def brief_entries(entries) -> list[tuple]:
    """(command, origin) of every agent.activity entry, for failure messages."""
    if not isinstance(entries, list):
        return [("<not a list>", repr(entries)[:80])]
    return [(e.get("command"), e.get("origin")) if isinstance(e, dict) else ("<not a dict>", repr(e)[:40])
            for e in entries]


def count_of(status) -> object:
    """`actions_last_minute` of an agent.status result, or a marker when absent."""
    return status.get("actions_last_minute", "<absent>") if isinstance(status, dict) else "<not a dict>"


def main() -> int:
    core = None
    a = None
    o = None
    try:
        section("boot aitm web (operator link enabled by the config's operator token)")
        cfg = CoreConfig(proxy_port=free_port(), browser_proxy_port=free_port(),
                         scope_entries=["127.0.0.1"])
        core = Aitm.web(cfg)
        ok(f"aitm web on :{core.web_port}, proxy :{cfg.proxy_port}")

        token = operator_bridge_token(core)
        # A missing token is a FAIL, never a skip: the operator half is the point.
        # The failure text masks any `t=<token>` it quotes; the token is never printed.
        if token is None:
            fail("no operator bridge token (`#t=<tok>&expect=operator`) in aitm web's output "
                 f"(stdout head: {redact_tokens((core.stdout_text() or '')[:300])!r})")
        ok("the operator bridge token was printed by aitm web")

        section("agent bridge A and operator bridge O open and subscribe; neither call is audited")
        a = WsBusClient.web_agent(core)
        o = WsBusClient.web_operator(core, token)
        # A repeated initialize is not an audited call (only tools/call is), so it
        # leaves the ring untouched; the reply names this connection's id and role.
        a_init = a.initialize()
        o_init = o.initialize()
        check(a_init.get("role") == "agent",
              f"A's bridge token resolves role=agent (got {a_init.get('role')!r})")
        check(o_init.get("role") == "operator",
              f"O's bridge token resolves role=operator (got {o_init.get('role')!r})")
        a_id = a_init.get("connection_id")
        o_id = o_init.get("connection_id")
        # A successful flow.subscribe is not audited (test_bus_push_ui_contract.py
        # section 5), so the ring is still empty after both.
        for who, ws in (("A", a), ("O", o)):
            sub = ws.call("flow.subscribe", {})
            check(isinstance(sub, dict) and isinstance(sub.get("sub_id"), int),
                  f"{who} flow.subscribe {{}} returned an integer sub_id: {sub!r}")

        section("1. O proxy.status -> a line on O's stream with origin 'operator'")
        o.call("proxy.status")
        o_own = wait_lines(o, is_call("proxy.status", "operator"))
        check(len(o_own) == 1,
              f"O's stream got exactly one proxy.status line with origin 'operator' within "
              f"{PUSH_WAIT_S:.0f}s (O's stream: {brief_lines(o)})")
        # Nothing is asserted about A's stream yet: no later line of A's has arrived,
        # so its silence would prove nothing (the barrier is step 2).

        section("2. A proxy.status is the barrier: A's own line arrives, and only then is A's stream judged")
        a.call("proxy.status")
        a_own = wait_lines(a, is_call("proxy.status", "mcp"))
        check(len(a_own) == 1,
              f"A's stream got its own proxy.status line with origin 'mcp' within "
              f"{PUSH_WAIT_S:.0f}s (A's stream: {brief_lines(a)})")
        # A's own line is in: anything the server meant to send A from step 1 is
        # either already here or was never sent. One more short drain closes the
        # window between "enqueued" and "read off the socket" for the earlier line.
        a.drain_notifications(timeout=1.0)
        operator_on_a = [p for p in lines_of(a) if p.get("origin") == "operator"]
        check(not operator_on_a,
              f"no line with origin 'operator' is on A's stream after the barrier "
              f"(A's stream: {brief_lines(a)})")
        # A's proxy.status line appears on O's stream as well.
        o_sees_a = wait_lines(o, is_call("proxy.status", "mcp"))
        check(len(o_sees_a) == 1,
              f"A's proxy.status line (origin 'mcp') is on O's stream within {PUSH_WAIT_S:.0f}s "
              f"(O's stream: {brief_lines(o)})")

        section("3. A agent.activity returns exactly one entry: A's own proxy.status")
        acts = a.call("agent.activity")
        check(isinstance(acts, list) and len(acts) == 1,
              f"A's first agent.activity returns 1 entry, not the operator's as well "
              f"(got {brief_entries(acts)})")
        check(acts[0].get("command") == "proxy.status" and acts[0].get("origin") == "mcp",
              f"that entry is command 'proxy.status', origin 'mcp' "
              f"(got {brief_entries(acts)})")
        # The ids are asserted to be real strings first, so equality below cannot be
        # satisfied vacuously by two absent ids.
        check(isinstance(a_id, str) and a_id != "" and isinstance(o_id, str) and o_id != "",
              f"each initialize reply carries a non-empty connection_id string "
              f"(A: {a_id!r}, O: {o_id!r})")
        check(a_id != o_id, f"A and O have different connection ids (A {a_id!r}, O {o_id!r})")
        check(acts[0].get("connection_id") == a_id,
              f"the entry's connection_id equals A's initialize id {a_id!r} "
              f"(got {acts[0].get('connection_id')!r})")

        section("4. O agent.activity returns three entries, oldest first: operator, mcp, mcp")
        o_acts = o.call("agent.activity")
        origins = [e.get("origin") for e in o_acts] if isinstance(o_acts, list) else o_acts
        check(isinstance(o_acts, list) and len(o_acts) == 3,
              f"O's agent.activity returns 3 entries (got {brief_entries(o_acts)})")
        check(origins == ["operator", "mcp", "mcp"],
              f"their origins are ['operator', 'mcp', 'mcp'] (got {origins!r})")
        check([e.get("command") for e in o_acts] == ["proxy.status", "proxy.status", "agent.activity"],
              f"their commands are O proxy.status, A proxy.status, A agent.activity "
              f"(got {brief_entries(o_acts)})")
        check([e.get("connection_id") for e in o_acts] == [o_id, a_id, a_id],
              f"each entry carries its caller's id: [O, A, A] = {[o_id, a_id, a_id]!r} "
              f"(got {[e.get('connection_id') for e in o_acts]!r})")

        section("5. A agent.status {exclude_self: true} counts nothing that is not another connection's")
        st = a.call("agent.status", {"exclude_self": True})
        check(count_of(st) == 0,
              f"A's actions_last_minute with exclude_self is 0: the ring holds 4 entries, "
              f"two are the operator's (hidden from A) and two are A's own (got {count_of(st)!r})")

        section("6. A agent.status {} counts what A may see, its own calls included")
        st = a.call("agent.status", {})
        check(count_of(st) == 3,
              f"A's actions_last_minute is 3 (A's proxy.status, agent.activity, and the "
              f"exclude_self agent.status; got {count_of(st)!r})")

        section("7. O agent.status {} counts everything: six audited calls precede it")
        st = o.call("agent.status", {})
        check(count_of(st) == 6,
              f"O's actions_last_minute is 6 (O proxy.status, A proxy.status, A agent.activity, "
              f"O agent.activity, A agent.status exclude_self, A agent.status; got {count_of(st)!r})")

        section("8. across the whole run A never held an operator line; O held every line")
        # Settle both streams, then judge every line each delivered over the run.
        a.drain_notifications(timeout=1.0)
        o.drain_notifications(timeout=1.0)
        a_stream = brief_lines(a)
        check(all(origin == "mcp" for _, origin in a_stream),
              f"every line on A's stream has origin 'mcp' (A's stream: {a_stream})")
        check(a_stream == [("proxy.status", "mcp"), ("agent.activity", "mcp"),
                           ("agent.status", "mcp"), ("agent.status", "mcp")],
              f"A's stream is exactly A's own four calls, in order (A's stream: {a_stream})")
        o_stream = brief_lines(o)
        check(o_stream == [("proxy.status", "operator"), ("proxy.status", "mcp"),
                           ("agent.activity", "mcp"), ("agent.activity", "operator"),
                           ("agent.status", "mcp"), ("agent.status", "mcp"),
                           ("agent.status", "operator")],
              f"O's stream is all seven audited calls, in order (O's stream: {o_stream})")
        ok("the audit stream's trust boundary holds over the real /bus bridge")
    finally:
        for ws in (a, o):
            if ws:
                ws.close()
        if core:
            core.stop()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
