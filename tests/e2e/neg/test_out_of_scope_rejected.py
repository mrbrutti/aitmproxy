#!/usr/bin/env python3
# e2e: tier=T1 surface=neg
"""Confinement: an active command aimed at an OUT-OF-SCOPE host is REFUSED, and
nothing leaks past the scope boundary — asserted on ground truth, never fixtures.

Scope is aitmproxy's core safety property: an authorized test must stay on the
hosts the operator put in scope and MUST NOT be steerable off-target (by a
compromised/confused agent, or even by the operator's own slip). This scenario
proves the guarantee at the real boundary, against a real core.

`request.send` (crates/aitm-plugins/src/mutate.rs) is an *active* reissue: it
crafts an HTTP request and sends it through the proxy's guarded client
(`PipelineClient`, crates/aitm-core/src/client.rs), which calls the scope/rate
guard's `check_active` FIRST (crates/aitm-core/src/guard.rs). An out-of-scope
authority is refused with `GuardError::OutOfScope` ("host <authority> is out of
scope", crates/aitm-core/src/error.rs) *before any network I/O*. The scope guard
is seeded from config at boot (crates/aitm-core/src/proxy.rs) and sits below the
role policy, so it binds the operator and the agent alike.

Two REAL loopback echo-record origins are the independent observers: one in
scope, one out of scope — both live and reachable, differing only in whether the
operator scoped them. Ground truth asserted:

  1. arranged state over the bus: `scope.list` holds the allowed authority and
     NOT the blocked one;
  2. positive control: an active `request.send` to the IN-SCOPE origin succeeds
     and the IN-SCOPE origin's OWN record shows it arrived (so the path works and
     the blocked origin is genuinely reachable — its silence later is scope, not a
     dead port);
  3. confinement: an active `request.send` to the OUT-OF-SCOPE origin is REFUSED
     for EVERY role (operator and agent) with a CLEAR scope error naming the host;
  4. the strongest observation: the out-of-scope origin's OWN record stays empty —
     confinement held at the network boundary, not merely in an error string.

Self-contained and repeatable: boots its own core on dedicated free ports with
the two upstreams on random ports, so it never collides with another run and
touches no global state.
"""

import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.upstream import Upstream  # noqa: E402

TAG = f"oos-{os.getpid()}-{int(time.time() * 1000)}"


def received_paths(up: Upstream) -> list:
    """The upstream's OWN record of request paths it actually served."""
    return [r["path"] for r in up.received]


def main() -> int:
    allowed = Upstream().start()  # the in-scope origin (independent observer)
    blocked = Upstream().start()  # the out-of-scope origin (independent observer)
    core = None
    clients = []
    try:
        section("boot: real core; ONLY the allowed upstream's host:port is in scope")
        # Scope EXACTLY the allowed authority. We deliberately do not scope a bare
        # `127.0.0.1` (a port-less entry covers every loopback port, incl. the
        # blocked one) nor the blocked upstream — so the blocked upstream is
        # genuinely out of scope even though it is a live, reachable loopback origin.
        cfg = CoreConfig(
            proxy_port=free_port(),
            scope_entries=[allowed.authority],
        )
        core = Aitm.server(cfg)
        ok(f"proxy :{cfg.proxy_port}, bus {core.bus_addr}")
        ok(f"allowed (in scope)    = {allowed.base}")
        ok(f"blocked (out of scope) = {blocked.base}")

        # The active-command role. Prefer the operator (it bypasses the agent
        # policy, so the ONLY thing that can refuse request.send is scope — an
        # unambiguous confinement claim), but always also drive the agent, since
        # confinement must bind it independent of the role policy.
        op = None
        try:
            op = BusClient.operator(core)
            clients.append(op)
        except Exception as e:  # noqa: BLE001
            ok(f"operator-over-loopback not available here ({type(e).__name__}); "
               "asserting the agent side (still fully scope-bound)")
        agent = BusClient.agent(core)
        clients.append(agent)

        primary = op or agent
        primary_role = "operator" if op else "agent"

        if "request.send" not in primary.tool_names():
            skip("request.send is not registered in this build; nothing to confine")

        section("arranged state (ground truth over the bus): scope holds the allowed authority, not the blocked one")
        if "scope.list" in primary.tool_names():
            scope_now = primary.call("scope.list")
            check(isinstance(scope_now, list), f"scope.list returns a list (was {type(scope_now).__name__})")
            check(allowed.authority in scope_now,
                  f"the allowed upstream {allowed.authority} IS in scope (scope.list={scope_now})")
            check(blocked.authority not in scope_now,
                  f"the blocked upstream {blocked.authority} is NOT in scope (scope.list={scope_now})")
        else:
            ok("scope.list not registered; relying on request.send behaviour + the upstreams' own records")

        section("positive control: an active request.send to the IN-SCOPE host really goes through")
        probe = f"/probe?{TAG}"
        st, res = primary.try_call(
            "request.send", {"authority": allowed.authority, "method": "GET", "path": probe}
        )
        check(st == "ok",
              f"[{primary_role}] request.send to the IN-SCOPE host SUCCEEDS (got {st}: {str(res)[:160]})")
        fid = res if st == "ok" else None
        check(isinstance(fid, str) and bool(fid),
              f"[{primary_role}] request.send returned a captured flow id ({fid!r})")
        # Independent observer: the in-scope upstream's OWN record shows it arrived.
        arrived = False
        deadline = time.time() + 5
        while time.time() < deadline:
            if any(probe in p for p in received_paths(allowed)):
                arrived = True
                break
            time.sleep(0.1)
        check(arrived,
              f"the IN-SCOPE upstream RECORDED the sent request (its own record: {received_paths(allowed)})")
        check(received_paths(blocked) == [],
              f"the out-of-scope upstream saw nothing from the positive control ({received_paths(blocked)})")

        section("confinement: an active request.send to the OUT-OF-SCOPE host is REFUSED, for every role")
        leak = f"/leak?{TAG}"
        roles = []
        if op:
            roles.append(("operator", op))
        roles.append(("agent", agent))
        for role_name, cli in roles:
            st, msg = cli.try_call(
                "request.send", {"authority": blocked.authority, "method": "GET", "path": leak}
            )
            check(st == "error",
                  f"[{role_name}] request.send to the OUT-OF-SCOPE host is REFUSED (got {st}: {str(msg)[:140]})")
            text = str(msg)
            check("out of scope" in text.lower(),
                  f"[{role_name}] the refusal is a CLEAR scope error, not a generic failure ({text[:180]})")
            check(blocked.authority in text,
                  f"[{role_name}] the refusal names the blocked authority {blocked.authority} ({text[:180]})")

        section("ground truth: confinement held at the NETWORK boundary — the out-of-scope origin never received anything")
        # A scope refusal returns before any send, so there is no async leak path;
        # a short settle still gives any hypothetical in-flight write a chance to land.
        time.sleep(0.3)
        leaked = received_paths(blocked)
        check(leaked == [],
              f"the out-of-scope upstream's OWN record is empty — nothing crossed the scope boundary ({leaked})")

        if not op:
            ok("note: operator path unavailable here, so confinement is proven for the agent role only")
        else:
            ok("confinement proven for BOTH the operator (bypasses role policy) and the agent")
    finally:
        for c in clients:
            try:
                c.close()
            except Exception:  # noqa: BLE001
                pass
        if core:
            core.stop()
        allowed.stop()
        blocked.stop()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
