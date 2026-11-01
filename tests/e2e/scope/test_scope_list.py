#!/usr/bin/env python3
# e2e: tier=T1 surface=scope
"""scope/test_scope_list -- `scope.list` reflects added entries, proven on GROUND TRUTH.

The claim under test is small ("the list shows what was added") so this script is
deliberately unforgiving about it. A listing is only worth anything if it is the
SAME set the guard enforces, so every entry the list shows (or stops showing) is
cross-checked against something the `scope.*` commands do not control:

  * three real HTTP upstreams THIS test runs on random loopback ports and whose
    server-side request records are the independent observer: A (added, then
    removed), B (added second: multiple entries, insertion order), C (never added:
    the control that must stay refused and must never receive a byte);
  * the real guard deciding real `request.send` calls from the AGENT connection
    -- `host X is out of scope` before an add, a captured flow id after it, refused
    again after the remove -- and `flow.detail` of the flow the core stored;
  * two roles (operator + agent) and a FRESH third connection reading the same
    list, so what is asserted is core state, not connection state.

Pinned semantics (crates/aitm-plugins/src/scope.rs, crates/aitm-core/src/guard.rs):
  * `scope.add` echoes the TRIMMED input (case kept); the guard stores it trimmed
    AND lowercased, deduplicated, appended to an ORDERED list;
  * `scope.list` is an array of strings in insertion order;
  * `scope.remove` matches regardless of case/whitespace, returns true iff an
    entry was dropped (false again on a second remove / a never-added entry);
  * a malformed entry ("", "has space", "ex.test/path", "ex.test:notaport") is
    refused `is not a host` and never widens scope;
  * widening is a human act: the AGENT's `scope.add` is refused fail-closed under
    the default `auto` policy and the list does not move.

Core: connects to the core the runner provides via env (`AITM_BUS_ADDR`,
`AITM_BUS_TOKEN` = agent token, `AITM_BUS_OPERATOR_TOKEN`; tests/e2e/README.md
contract) and boots nothing in that case. Without `AITM_BUS_ADDR` it boots one
dedicated core on free ports like every other `aitm_e2e` suite, so the script is
runnable by hand and under tests/e2e/run.py. Parallel-safe on a shared core: it
only adds its own unique `127.0.0.1:<random port>` entries and a unique wildcard,
compares the list by the entries it owns plus order-preservation of everything
else, and removes every entry it added on exit (success or failure).

Exit: 0 pass, 1 fail, 77 skip (the reason is printed).
"""

from __future__ import annotations

import os
import socket
import sys
import time
import types
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient, BusError, ToolError  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.upstream import Upstream  # noqa: E402

OUT_OF_SCOPE = "is out of scope"  # GuardError::OutOfScope: "host X is out of scope"
NOT_A_HOST = "is not a host"  # scope.add validation: "... is not a host, host:port, or *.wildcard"
# Transient guard verdicts on the 127.0.0.1 bucket every parallel test shares; a
# retry keeps them from ever being mistaken for a scope verdict.
TRANSIENT = ("rate limited", "host disabled", "concurrency")
MALFORMED = ["", "   ", "has space", "ex.test/path", "ex.test:notaport"]
SETTLE = 0.4  # grace after a refusal: a refuse-but-fire-anyway bug would land here


def unique(prefix: str = "e2e") -> str:
    """A collision-free marker (paths, labels): tests share one core and one flow store."""
    return f"{prefix}-{os.getpid()}-{uuid.uuid4().hex[:8]}"


# ---------------------------------------------------------------------------
# the core: the runner's (via env) or, failing that, a dedicated one


class EnvCore:
    """The core the runner provides through the environment, shaped like
    `aitm_e2e.core.Aitm` so `BusClient.operator(core)` / `.agent(core)` work
    unchanged. Boots nothing; `stop()` is a no-op (it is not ours to stop)."""

    owned = False

    def __init__(self, addr: str, agent_token: str, operator_token: str):
        host, sep, port = addr.strip().rpartition(":")
        if not sep or not host or not port.isdigit():
            fail(f"AITM_BUS_ADDR must be host:port, got {addr!r}")
        self.bus_addr = (host.strip("[]"), int(port))
        self.cfg = types.SimpleNamespace(agent_token=agent_token, operator_token=operator_token)

    def stop(self) -> None:
        pass


def acquire_core():
    """(core, description). Env first; a dedicated boot only when no runner core exists."""
    addr = os.environ.get("AITM_BUS_ADDR")
    if addr:
        agent_token = os.environ.get("AITM_BUS_TOKEN")
        op_token = os.environ.get("AITM_BUS_OPERATOR_TOKEN")
        if not agent_token:
            fail("AITM_BUS_ADDR is set but AITM_BUS_TOKEN (the agent token) is not")
        if not op_token:
            skip("the runner's core has no AITM_BUS_OPERATOR_TOKEN: scope.add needs the operator "
                 "role (the agent is refused fail-closed), so added entries cannot be driven")
        return EnvCore(addr, agent_token, op_token), f"runner-provided core at {addr} (nothing booted)"
    cfg = CoreConfig(proxy_port=free_port(), browser_proxy_port=free_port(), allow_agent_widen=False)
    core = Aitm.server(cfg)
    core.owned = True  # type: ignore[attr-defined]
    return core, f"dedicated core (no AITM_BUS_ADDR in env): bus {core.bus_addr}, proxy 127.0.0.1:{cfg.proxy_port}"


# ---------------------------------------------------------------------------
# helpers


def listing(bus: BusClient) -> list:
    """`scope.list` as the typed array of strings the schema promises (else FAIL)."""
    v = bus.call("scope.list")
    if not isinstance(v, list) or not all(isinstance(e, str) for e in v):
        fail(f"scope.list did not return an array of strings: {v!r}")
    return v


def send(bus: BusClient, authority: str, path: str):
    """`request.send` through the core's guarded client: ('ok', flow_id) or
    ('error', text). A transient throttle is retried, never read as a verdict."""
    st, val = "error", "request.send was never attempted"
    for _ in range(10):
        st, val = bus.try_call("request.send", {"authority": authority, "path": path})
        if st == "ok" or not any(s in str(val) for s in TRANSIENT):
            return st, val
        time.sleep(0.3)
    return st, val


def hits(up: Upstream, tag: str) -> list:
    """What upstream `up` REALLY received carrying `tag` -- its own record."""
    return [r for r in up.received if tag in r["path"]]


def survivors_in_order(before: list, after: list) -> bool:
    """Entries present in both snapshots keep their relative order (an append or a
    single removal never reorders the rest). Robust to other tests' concurrent
    adds/removes on a shared core; catches a clobbered or rebuilt list."""
    return [e for e in after if e in before] == [e for e in before if e in after]


def assert_appended(before: list, after: list, entry: str, exact: bool) -> None:
    check(entry not in before, f"{entry!r} was not listed before the add")
    check(after.count(entry) == 1, f"scope.list shows {entry!r} exactly once (count {after.count(entry)})")
    check(survivors_in_order(before, after), f"every pre-existing entry kept its order: {after}")
    last_old = max((after.index(e) for e in before if e in after), default=-1)
    check(after.index(entry) > last_old, f"{entry!r} was APPENDED after every pre-existing entry (index {after.index(entry)})")
    if exact:
        check(after == before + [entry], f"dedicated core: list is exactly before + [{entry!r}]: {after}")


def assert_dropped(before: list, after: list, entry: str, exact: bool) -> None:
    check(entry in before, f"{entry!r} was listed before the remove")
    check(entry not in after, f"scope.list no longer shows {entry!r}: {after}")
    check(survivors_in_order(before, after), f"the remaining entries kept their order: {after}")
    if exact:
        check(after == [e for e in before if e != entry], f"dedicated core: list is exactly before minus {entry!r}")


# ---------------------------------------------------------------------------


def main() -> int:
    core, how = acquire_core()
    exact = bool(getattr(core, "owned", False))  # a dedicated core is deterministic: assert whole lists
    ups = []
    op = agent = None
    owned_entries: list = []  # everything this test may have added: removed on exit, whatever happens

    def cleanup() -> None:
        if op is not None:
            for e in owned_entries:
                try:
                    op.try_call("scope.remove", {"host": e})
                except Exception:  # noqa: BLE001 -- cleanup must not mask the verdict
                    pass
        for b in (op, agent):
            if b is not None:
                try:
                    b.close()
                except Exception:  # noqa: BLE001
                    pass
        for u in ups:
            try:
                u.stop()
            except Exception:  # noqa: BLE001
                pass
        try:
            core.stop()
        except Exception:  # noqa: BLE001
            pass

    try:
        section(f"arrange: {how}; three real upstreams (A added+removed, B added, C never)")
        for _ in range(3):
            ups.append(Upstream().start())
        a, b, c = ups
        A, B, C = a.authority, b.authority, c.authority
        tag = unique("scopelist")
        label = unique("lbl")  # lowercase; `.invalid` never resolves (RFC 6761): nothing is contacted
        wild = f"*.{label}.invalid"  # the normalized form the list must show
        wild_input = f"  *.{label.upper()}.INVALID  "  # whitespace + case: what we actually send
        owned_entries[:] = [A, B, C, wild, wild_input.strip(), wild_input.strip().lower()]
        own = set(owned_entries)

        def mine(listed: list) -> list:
            return [e for e in listed if e in own]

        op = BusClient.operator(core)
        agent = BusClient.agent(core)
        ok(f"operator + agent connected; A={A} B={B} C={C} wildcard={wild}")

        section("the live registry exposes scope.list/add/remove with the documented shapes")
        tools = {t["name"]: t for t in op.tools()}
        for name in ("scope.list", "scope.add", "scope.remove"):
            check(name in tools, f"{name} is registered on the live core")
        for name in ("scope.add", "scope.remove"):
            schema = tools[name].get("inputSchema") or {}
            check("host" in (schema.get("properties") or {}) and "host" in (schema.get("required") or []),
                  f"{name} inputSchema requires `host`")
        check(not (tools["scope.list"].get("inputSchema") or {}).get("required"),
              "scope.list inputSchema requires no argument")

        section("baseline: operator and agent read the same list; none of our entries is in it")
        base_op, base_agent = listing(op), listing(agent)
        check(base_op == base_agent, f"operator and agent see the same scope.list ({len(base_op)} entries)")
        check(not mine(base_op), f"none of this test's unique entries is pre-listed: {base_op}")
        try:
            policy = str(op.call("agent.status").get("policy"))
        except (BusError, ToolError, AttributeError) as e:  # an older core without agent.status
            policy = "unknown"
            ok(f"agent.status unavailable ({type(e).__name__}); policy treated as unknown")
        ok(f"agent policy: {policy}")
        # The actor whose sends scope must confine: the agent, unless its policy
        # forbids Write commands outright (readonly/paused), then the operator.
        actor = agent if policy in ("auto", "all", "ask", "unknown") else op
        ok(f"active sends are driven as the {'AGENT' if actor is agent else 'OPERATOR (agent policy forbids Write)'}")
        # A runner core whose seed scope already covers all of 127.0.0.1 (a bare-host
        # entry) cannot show the "refused until added" half on our ports; detect it
        # with a real probe to the never-added control C rather than assuming.
        st, msg = send(actor, C, f"/probe?{unique('probe')}")
        loopback_open = st == "ok"
        if loopback_open:
            ok("NOTE: this core already admits every 127.0.0.1 port (seed scope); out-of-scope refusals are not asserted")
        else:
            check(OUT_OF_SCOPE in msg, f"baseline: an unlisted loopback port is refused out of scope: {msg[:120]}")

        section("fail-closed: the AGENT cannot widen scope, and scope.list does not move")
        if policy == "ask":
            ok("policy `ask` parks a Sensitive agent call for operator approval; not driven (it would block a shared core)")
        else:
            before = listing(op)
            probe = BusClient.agent(core)  # throwaway: a parked/hung probe must not poison `agent`
            try:
                st, msg = probe.try_call("scope.add", {"host": A})
            except (BusError, OSError, socket.timeout) as e:
                st, msg = "error", f"{type(e).__name__}: {e}"
            finally:
                probe.close()
            if st == "ok":
                # Only legitimate when the operator opened the config gate under `all`.
                check(policy in ("all", "unknown"), f"agent scope.add succeeded under policy {policy!r}: the fail-closed gate is broken")
                ok("policy `all` + scope.allow_agent_widen=true: the operator opened the gate; A is removed again before we go on")
                check(op.call("scope.remove", {"host": A}) is True, "the agent-added A is removed again")
            else:
                check("refused" in msg, f"agent scope.add is refused fail-closed: {msg[:160]}")
                after = listing(op)
                check(A not in after and mine(after) == mine(before), f"...and scope.list did not move: {after}")
                check(survivors_in_order(before, after), "...and nothing else was reordered")

        section("malformed entries are refused `is not a host` and never widen scope")
        before = listing(op)
        for bad in MALFORMED:
            st, msg = op.try_call("scope.add", {"host": bad})
            check(st == "error" and NOT_A_HOST in msg, f"scope.add {bad!r} refused: {msg[:120]}")
        try:
            r = op.call("scope.add", {})
            fail(f"scope.add without `host` was accepted: {r!r}")
        except (BusError, ToolError) as e:  # JSON-RPC -32602 invalid params, or the command's own error
            ok(f"scope.add without `host` is rejected ({type(e).__name__}: {str(e)[:100]})")
        after = listing(op)
        check(mine(after) == [] and survivors_in_order(before, after), f"scope.list unchanged after the bad inputs: {after}")

        section("scope.add A: the echo, the list and the guard's ENFORCEMENT agree")
        path_pre, path_a = f"/pre?{tag}", f"/a?{tag}"
        if not loopback_open:
            st, msg = send(actor, A, path_pre)
            check(st == "error" and OUT_OF_SCOPE in msg, f"before the add, request.send to A is refused out of scope: {msg[:120]}")
            time.sleep(SETTLE)
            check(hits(a, tag) == [], f"...and upstream A received nothing: {hits(a, tag)}")
        before = listing(op)
        echo = op.confirm("scope.add", {"host": A})
        check(echo == A, f"scope.add echoes the entry it added ({echo!r})")
        after = listing(op)
        assert_appended(before, after, A, exact)
        check(listing(agent).count(A) == 1, "the AGENT's scope.list shows A too (core state, not connection state)")
        st, fid = send(actor, A, path_a)
        check(st == "ok" and isinstance(fid, str) and bool(fid), f"after the add, request.send to A is admitted and returns a flow id ({fid!r})")
        got = hits(a, tag)
        check([r["path"] for r in got] == [path_a], f"upstream A really received exactly that one request: {[r['path'] for r in got]}")
        check(got and got[0]["headers"].get("host") == A, f"...addressed to A (Host: {got[0]['headers'].get('host') if got else None})")
        detail = op.call("flow.detail", {"id": fid, "body": "none"})
        req, resp = detail.get("request") or {}, detail.get("response") or {}
        check((req.get("authority"), req.get("path")) == (A, path_a), f"the stored flow is that send: {req.get('authority')} {req.get('path')}")
        check(resp.get("status") == 200, f"...and it completed with A's 200 (status {resp.get('status')})")
        if not loopback_open:
            st, msg = send(actor, C, f"/c?{tag}")
            check(st == "error" and OUT_OF_SCOPE in msg, f"control C (same IP, other port, never added) is still refused: {msg[:120]}")
            time.sleep(SETTLE)
            check(hits(c, tag) == [], "...and upstream C received nothing")

        section("normalization + dedup: one lowercase entry; the echo is the trimmed input")
        before = listing(op)
        echo = op.confirm("scope.add", {"host": wild_input})
        check(echo == wild_input.strip(), f"scope.add echoes the TRIMMED input, case kept ({echo!r})")
        after = listing(op)
        assert_appended(before, after, wild, exact)
        check(wild_input.strip() not in after, f"the raw-case spelling is not a separate entry: {after}")
        before = after
        echo = op.confirm("scope.add", {"host": wild.upper()})
        check(echo == wild.upper(), f"re-adding the same entry in another case is accepted ({echo!r})")
        after = listing(op)
        check(after.count(wild) == 1 and wild.upper() not in after, f"...but the list still holds it ONCE, lowercase: {after}")
        check(mine(after) == mine(before) and survivors_in_order(before, after), "...and nothing moved (dedup, no reorder)")
        if exact:
            check(after == before, "dedicated core: the list is byte-for-byte unchanged by the duplicate add")
        before = after
        echo = op.confirm("scope.add", {"host": A})
        after = listing(op)
        check(echo == A and after.count(A) == 1 and mine(after) == mine(before), f"re-adding A is idempotent: {after}")

        section("a second real host B: multiple entries, insertion order, each enforced on its own")
        before = listing(op)
        echo = op.confirm("scope.add", {"host": B})
        check(echo == B, f"scope.add echoes B ({echo!r})")
        after = listing(op)
        assert_appended(before, after, B, exact)
        check(mine(after) == [A, wild, B], f"this test's entries are listed in insertion order [A, wildcard, B]: {mine(after)}")
        path_b = f"/b?{tag}"
        st, fid_b = send(actor, B, path_b)
        check(st == "ok" and isinstance(fid_b, str) and bool(fid_b), f"request.send to B is admitted ({fid_b!r})")
        check([r["path"] for r in hits(b, tag)] == [path_b], f"upstream B really received exactly that request: {[r['path'] for r in hits(b, tag)]}")
        if not loopback_open:
            st, msg = send(actor, C, f"/c2?{tag}")
            check(st == "error" and OUT_OF_SCOPE in msg, "control C is still refused with two entries present")
            time.sleep(SETTLE)
            check(hits(c, tag) == [], "...and upstream C still received nothing")
        fresh = BusClient.agent(core)
        try:
            view_fresh, view_agent, view_op = mine(listing(fresh)), mine(listing(agent)), mine(listing(op))
        finally:
            fresh.close()
        check(view_fresh == view_agent == view_op == [A, wild, B], f"operator, agent and a FRESH connection all list [A, wildcard, B]: {view_fresh}")

        section("scope.remove: the list drops the entry, enforcement follows, remove is idempotent")
        before = listing(op)
        check(op.call("scope.remove", {"host": A}) is True, "scope.remove A returns true")
        after = listing(op)
        assert_dropped(before, after, A, exact)
        check(mine(after) == [wild, B], f"the remaining entries are [wildcard, B] in order: {mine(after)}")
        if not loopback_open:
            st, msg = send(actor, A, f"/post?{tag}")
            check(st == "error" and OUT_OF_SCOPE in msg, f"request.send to A is refused out of scope again: {msg[:120]}")
            time.sleep(SETTLE)
            check([r["path"] for r in hits(a, tag)] == [path_a], "...and upstream A received nothing more (still exactly the one earlier hit)")
        st, fid_b2 = send(actor, B, f"/b2?{tag}")
        check(st == "ok" and isinstance(fid_b2, str) and fid_b2 != fid_b, "B is unaffected by A's removal: a second send is admitted")
        check(len(hits(b, tag)) == 2, f"upstream B now holds exactly two hits: {[r['path'] for r in hits(b, tag)]}")
        before = listing(op)
        check(op.call("scope.remove", {"host": A}) is False, "a second scope.remove A returns false (nothing to drop)")
        check(op.call("scope.remove", {"host": C}) is False, "scope.remove of a never-added entry returns false")
        after = listing(op)
        check(mine(after) == mine(before) and survivors_in_order(before, after), f"...and neither moved the list: {after}")
        before = after
        alt = f"  *.{label.upper()}.invalid "  # another spelling of the wildcard
        check(op.call("scope.remove", {"host": alt}) is True, f"scope.remove matches the wildcard regardless of case/whitespace ({alt!r})")
        after = listing(op)
        assert_dropped(before, after, wild, exact)
        before = after
        check(op.call("scope.remove", {"host": B}) is True, "scope.remove B returns true")
        after = listing(op)
        assert_dropped(before, after, B, exact)
        check(mine(after) == [], f"none of this test's entries remains: {after}")
        check(mine(listing(agent)) == [], "...as the agent sees it too")
        if exact:
            check(after == base_op, f"dedicated core: scope.list is back to the baseline {base_op}")
        if not loopback_open:
            st, msg = send(actor, B, f"/b3?{tag}")
            check(st == "error" and OUT_OF_SCOPE in msg, "with B removed, request.send to B is refused out of scope")
            time.sleep(SETTLE)
            check(len(hits(b, tag)) == 2, "...and upstream B received nothing more")

        enforcement = ("the guard enforced exactly what the list showed (A: 1 hit while listed, C: 0 hits ever, "
                       "B: 2 hits while listed)" if not loopback_open else
                       "admission verified (this core's seed scope already covers 127.0.0.1, refusals not asserted)")
        print(f"\nPASS: scope.list tracked add/dedup/order/remove for {A}, {wild}, {B}; {enforcement}", flush=True)
        return 0
    finally:
        cleanup()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
