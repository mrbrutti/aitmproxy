#!/usr/bin/env python3
# e2e: tier=T1 surface=audit
"""Audit-line identity on a REAL running core: the server-assigned connection id,
the `exclude_self` count, and the bounded `client_label`.

Boots its OWN fresh core (`Aitm.server`), so the audit ring starts empty and
only this test's three connections ever write to it. That is what makes the
literal counts below exact: no pre-count read of the ring is possible (it would
add an operator entry and move the operator's count), so the exact numbers are
also the freshness check. An entry is recorded AFTER its call returns, so a call
never counts itself.

What is proven, in call order (agents A and B, operator O; ring size after each):

 1-3  A `scope.list` x3                                         ring 3
 4-5  B `scope.list` x2                                         ring 5
 6    A `agent.status {exclude_self: true}` -> 2                ring 6
      (the five agent entries minus A's own three)
 7    A `agent.status {}` -> 6                                  ring 7
 8    O `agent.status {}` -> 7                                  ring 8
      (O has made no audited call yet, so the count is the whole ring)
 9    O `agent.activity`: every entry labelled A carries A's `initialize`
      connection id, every entry labelled B carries B's; the two ids are
      different non-empty strings of at most 64 bytes.
 10   The label step, LAST so the counts above stay exact: a client named
      `"x" * (1 << 20)` makes one call and the operator's `agent.activity` entry
      for it (found by that client's own `initialize` id) has a `client_label`
      of exactly 64 characters, `"x" * 64`. The label must be bounded at
      ingestion: stored whole, a 16 MiB name times the 6144 entries of the
      default ring (4096 evidence plus 2048 routine) would be 96 GiB reachable
      with one token.

Every assertion on the oversized label compares lengths or a 64-character
prefix, so a failure never prints 1 MiB.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section  # noqa: E402
from aitm_e2e.bus import BusClient, BusError, ToolError  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402

LABEL_A = "aitm-e2e-ident-a"
LABEL_B = "aitm-e2e-ident-b"
MAX_LABEL_CHARS = 64  # aitm_core::MAX_CLIENT_LABEL_CHARS: characters, not bytes
MAX_ID_BYTES = 64  # D1: the id is at most 64 bytes of printable ASCII
BIG_LABEL_BYTES = 1 << 20


def connect(core: Aitm, label: str) -> BusClient:
    """An AGENT-token connection to the core's bus, named `label`
    (`initialize.clientInfo.name`, which becomes the audit entry's `client_label`)."""
    host, port = core.bus_addr
    return BusClient(host, port, core.cfg.agent_token, client_name=label).connect()


def scope_list(bus: BusClient, who: str) -> None:
    try:
        listed = bus.call("scope.list")
    except (BusError, ToolError) as e:
        fail(f"{who} scope.list failed: {e}")
    check(isinstance(listed, list), f"{who} scope.list answered a list (got {type(listed).__name__})")


def actions_last_minute(bus: BusClient, who: str, args: dict) -> int:
    """`agent.status`'s `actions_last_minute`. A protocol-level refusal (an older
    core rejects the unknown `exclude_self` argument with JSON-RPC -32602) is a
    FAIL naming the call, not a traceback."""
    try:
        res = bus.call("agent.status", args)
    except (BusError, ToolError) as e:
        fail(f"{who} agent.status {args} was refused: {e}")
    n = res.get("actions_last_minute") if isinstance(res, dict) else None
    check(isinstance(n, int) and not isinstance(n, bool),
          f"{who} agent.status {args} answered an integer actions_last_minute (got {n!r})")
    return n


def activity(bus: BusClient, who: str) -> list[dict]:
    try:
        res = bus.call("agent.activity", {})
    except (BusError, ToolError) as e:
        fail(f"{who} agent.activity failed: {e}")
    check(isinstance(res, list), f"{who} agent.activity answered an array (got {type(res).__name__})")
    return res


def connection_id(bus: BusClient, who: str) -> str:
    """The id the server assigned to this connection, as `initialize` reports it.
    A repeated `initialize` returns the same id; `initialize` is not a tools/call,
    so asking never adds an audit entry."""
    res = bus.initialize()
    cid = res.get("connection_id") if isinstance(res, dict) else None
    check(isinstance(cid, str) and cid != "",
          f"{who} initialize result carries a non-empty string connection_id (got {type(cid).__name__})")
    check(len(cid.encode("utf-8")) <= MAX_ID_BYTES,
          f"{who} connection_id is at most {MAX_ID_BYTES} bytes (got {len(cid.encode('utf-8'))})")
    return cid


def main() -> int:
    core = None
    a = b = op = x = None
    try:
        section("boot: a fresh real aitm core of our own, three connections (A, B agent-token; O operator)")
        cfg = CoreConfig(
            proxy_port=free_port(),
            browser_proxy_port=free_port(),
            scope_entries=["127.0.0.1"],
        )
        core = Aitm.server(cfg)
        ok(f"proxy on 127.0.0.1:{cfg.proxy_port}, bus on {core.bus_addr}")
        a = connect(core, LABEL_A)
        b = connect(core, LABEL_B)
        op = BusClient.operator(core)
        ok(f"A is `{LABEL_A}`, B is `{LABEL_B}`, O is the operator (none has made an audited call yet)")

        # ---------------------------------------------------------------
        section("1-5. A `scope.list` x3, then B `scope.list` x2 (five agent entries in the ring)")
        for i in range(3):
            scope_list(a, f"A #{i + 1}")
        for i in range(2):
            scope_list(b, f"B #{i + 1}")
        ok("A made 3 audited calls, B made 2")

        # ---------------------------------------------------------------
        section("6. A `agent.status {exclude_self: true}`: the asker's own three entries are left out")
        n = actions_last_minute(a, "A", {"exclude_self": True})
        check(n == 2, f"actions_last_minute is 2 (5 agent entries minus A's 3), got {n}")

        # ---------------------------------------------------------------
        section("7. A `agent.status {}`: without exclude_self every entry counts, A's own included")
        n = actions_last_minute(a, "A", {})
        check(n == 6, f"actions_last_minute is 6 (5 scope.list + A's step-6 agent.status), got {n}")

        # ---------------------------------------------------------------
        section("8. O `agent.status {}`: the operator sees the whole ring")
        n = actions_last_minute(op, "O", {})
        check(n == 7, f"actions_last_minute is 7 (O has made no audited call yet), got {n}")

        # ---------------------------------------------------------------
        section("9. every audit entry carries the server-assigned id of the connection that made it")
        id_a = connection_id(a, "A")
        id_b = connection_id(b, "B")
        check(id_a != id_b, "A and B were assigned different connection ids")
        entries = activity(op, "O")
        by_a = [e for e in entries if e.get("client_label") == LABEL_A]
        by_b = [e for e in entries if e.get("client_label") == LABEL_B]
        # A: 3 scope.list + the step-6 and step-7 agent.status. B: 2 scope.list.
        check(len(by_a) == 5, f"the ring holds 5 entries labelled `{LABEL_A}` (got {len(by_a)})")
        check(len(by_b) == 2, f"the ring holds 2 entries labelled `{LABEL_B}` (got {len(by_b)})")
        ids_a = sorted({str(e.get("connection_id")) for e in by_a})
        ids_b = sorted({str(e.get("connection_id")) for e in by_b})
        check(ids_a == [id_a], f"every `{LABEL_A}` entry carries A's initialize id (got {ids_a}, want {[id_a]})")
        check(ids_b == [id_b], f"every `{LABEL_B}` entry carries B's initialize id (got {ids_b}, want {[id_b]})")

        # ---------------------------------------------------------------
        section("10. an oversized client label is cut to 64 characters at ingestion (runs last: counts stay exact)")
        host, port = core.bus_addr
        x = BusClient(host, port, core.cfg.agent_token, client_name="x" * BIG_LABEL_BYTES).connect()
        ok(f"connected a client whose initialize name is {BIG_LABEL_BYTES} bytes")
        scope_list(x, "X")
        id_x = connection_id(x, "X")
        check(id_x not in (id_a, id_b), "X was assigned a connection id of its own")
        entries = activity(op, "O")
        mine = [e for e in entries if e.get("connection_id") == id_x]
        check(len(mine) == 1,
              f"exactly one entry carries X's connection id (got {len(mine)}; "
              f"{len(entries)} entries, label lengths {sorted({len(e.get('client_label') or '') for e in entries})})")
        label = mine[0].get("client_label")
        check(isinstance(label, str), f"X's entry has a string client_label (got {type(label).__name__})")
        check(len(label) == MAX_LABEL_CHARS,
              f"X's client_label is {MAX_LABEL_CHARS} characters, not {BIG_LABEL_BYTES} (got {len(label)})")
        check(label == "x" * MAX_LABEL_CHARS,
              f"X's client_label is the first {MAX_LABEL_CHARS} characters of its name")
    finally:
        for c in (x, a, b, op):
            if c:
                c.close()
        if core:
            core.stop()

    ok("audit identity: per-connection ids on entries, exclude_self counts, label capped at 64 characters")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
