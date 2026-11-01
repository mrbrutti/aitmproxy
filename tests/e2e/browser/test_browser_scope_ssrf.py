#!/usr/bin/env python3
# e2e: tier=T1 surface=browser
"""browser/browser_scope_ssrf -- `browser.navigate` honors the SSRF / private-network
guard: a loopback (or RFC1918) target is REFUSED unless the policy's scope union lifts
the block for that exact host, and lifting scope makes the very same navigation go through.

The guard lives inside the command (crates/aitm-browser/src/ssrf.rs::check_url ->
crates/aitm-core/src/guard.rs::ssrf_check). The default policy blocks loopback + private
and lifts the block only for an EXACT scope entry (a scoped hostname that resolves private
does NOT lift it -- the DNS-rebinding rule), so the loopback aitm-testtarget is the subject.

Ground truth, never fixtures:
  * BLOCKED -- with the target out of scope, a real browser.navigate over the real bus is
    refused with the real SSRF guard error, and the core's own flow store shows NO flow:
    the block precedes any dial, so nothing was ever sent.
  * ALLOWED -- the operator widens scope by the exact host:port and the SAME navigation is
    no longer SSRF-refused. With a real obscura present it completes and the store holds the
    browser's real GET + the upstream's 200; WITHOUT obscura the refusal is merely "no
    browser configured", proving the guard itself lifted.

This cell RUNS HEADLESS: it proves the guard at the command level and accepts the engine-
absent error as the "guard lifted" signal, so it needs no obscura (with AITM_OBSCURA=1 the
scoped navigation MUST complete instead). scope.add/remove are Sensitive, so it uses the
operator token. Converted from the dead _lib/mcp draft harness onto aitm_e2e: self-boots
its own core + seeded loopback Target with an EMPTY scope (so the target starts blocked).
Soft-assertion battery; exit 0 pass / 1 fail / 77 skip.
"""
from __future__ import annotations

import ipaddress
import os
import socket
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import fail, free_port, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient, BusError, ToolError  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.target import Target  # noqa: E402

CAPTURE_BUDGET = 20.0  # seconds for a scoped navigation's flow to land in the store
NO_FLOW_SETTLE = 1.5   # seconds a (wrongly) dialed blocked navigation would need to appear
SSRF_HINTS = ("blocked by the ssrf guard", "private or loopback", "out of scope")
NO_BROWSER_HINTS = ("no browser is configured", "obscura", "was not found", "no browser")

_failures: list[str] = []


def expect(cond, msg: str, detail="") -> bool:
    if cond:
        ok(msg)
        return True
    line = f"  [FAIL] {msg}"
    if detail != "":
        line += f"   -- {str(detail)[:200]}"
    print(line, flush=True)
    _failures.append(msg)
    return False


def confirm_call(bus, name, args):
    """An operator call that may need the two-phase confirm handshake; returns
    (ok: bool, result_or_error)."""
    try:
        return True, bus.confirm(name, args)
    except (ToolError, BusError) as e:
        return False, str(e)


def scope_names(entries):
    return [e if isinstance(e, str) else (e or {}).get("host", "") for e in (entries or [])]


def is_ssrf_refusal(msg):
    m = str(msg).lower()
    return any(h in m for h in SSRF_HINTS)


def resolve_ips(host, port):
    try:
        return sorted({info[4][0] for info in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)})
    except OSError:
        return []


def classify_private(host, addrs):
    if host == "localhost":
        return True
    cands = list(addrs)
    try:
        cands.append(str(ipaddress.ip_address(host)))
    except ValueError:
        pass
    for a in cands:
        try:
            ip = ipaddress.ip_address(a)
        except ValueError:
            continue
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_unspecified:
            return True
    return False


def wait_for_row(bus, pred, timeout):
    deadline = time.monotonic() + timeout
    while True:
        for row in bus.call("flow.table").get("flows", []):
            if pred(row):
                return row
        if time.monotonic() > deadline:
            return None
        time.sleep(0.25)


def find_row(bus, marker):
    return next((r for r in bus.call("flow.table").get("flows", []) if marker in (r.get("path") or "")), None)


def main() -> int:
    tgt = Target("vulnerable")
    core = agent = op = None
    orig: list = []
    try:
        section("boot: aitm core + seeded loopback target with an EMPTY scope (target starts blocked)")
        cfg = CoreConfig(proxy_port=free_port(), scope_entries=[], allow_agent_widen=False)
        core = Aitm.server(cfg)
        agent = BusClient.agent(core)
        op = BusClient.operator(core)
        if "browser.navigate" not in agent.tool_names():
            skip("this core registers no browser.* tools (built without the browser feature)")

        target = tgt.base.rstrip("/")
        u = urlsplit(target)
        host = (u.hostname or "").lower()
        port = u.port or 80
        authority = tgt.authority  # host:port as written -- what the flow records
        ips = resolve_ips(host, port)
        if not classify_private(host, ips):
            skip(f"target {target!r} is not loopback/private; this test proves the private-network block")

        lift_set = {authority.lower(), host, "localhost"}
        for ip in ips:
            lift_set.add(ip.lower())
            lift_set.add(f"{ip}:{port}".lower())

        orig = scope_names(op.call("scope.list"))
        for e in list(orig):
            if e.strip().lower() in lift_set:
                confirm_call(op, "scope.remove", {"host": e})
        after = {x.strip().lower() for x in scope_names(op.call("scope.list"))}
        expect(not (after & lift_set), "the loopback target is not in scope", sorted(after))

        section("PHASE 1 BLOCKED: an out-of-scope loopback navigation is SSRF-refused, nothing dialed")
        blk = f"ssrf-blocked-{uuid.uuid4().hex[:8]}"
        st_a, msg_a = agent.try_call("browser.navigate", {"url": f"{target}/search?q={blk}"})
        expect(st_a == "error", "agent browser.navigate to the unscoped loopback target is refused", msg_a)
        expect(st_a == "error" and is_ssrf_refusal(msg_a),
               "the refusal is the SSRF / private-network guard (not a transport/engine fault)", str(msg_a)[:200])
        blk_op = f"ssrf-blocked-op-{uuid.uuid4().hex[:8]}"
        st_o, msg_o = op.try_call("browser.navigate", {"url": f"{target}/search?q={blk_op}"})
        expect(st_o == "error" and is_ssrf_refusal(msg_o),
               "operator browser.navigate is SSRF-blocked too (guard is inside the command)", str(msg_o)[:200])
        time.sleep(NO_FLOW_SETTLE)
        expect(find_row(agent, blk) is None and find_row(agent, blk_op) is None,
               "the blocked navigation produced NO captured flow (nothing was ever dialed)",
               "a flow carrying the blocked marker would mean egress happened")

        section("PHASE 2 ALLOWED: the operator widens scope by exact host:port; the guard lifts")
        ok_add, res_add = confirm_call(op, "scope.add", {"host": authority})
        expect(ok_add, "operator widens scope to the loopback target (host:port)", res_add)
        expect(authority in scope_names(op.call("scope.list")), "the lift entry is now in scope", authority)

        allow = f"ssrf-allowed-{uuid.uuid4().hex[:8]}"
        url_allow = f"{target}/search?q={allow}"
        st_n, nav = agent.try_call("browser.navigate", {"url": url_allow})
        if st_n == "ok":
            expect((nav.get("final_url") or "").startswith(url_allow), "the scoped navigation landed on the target", nav)
            row = wait_for_row(agent, lambda r: allow in (r.get("path") or ""), CAPTURE_BUDGET)
            expect(row is not None, f"the scoped navigation was captured as a real flow within {CAPTURE_BUDGET:.0f}s", allow)
            if row is not None:
                expect((row.get("kind"), row.get("method"), row.get("status")) == ("http", "GET", 200)
                       and host in (row.get("authority") or "").lower(),
                       "the captured flow is the browser's real GET with the upstream's real 200", row)
        else:
            msg_n = str(nav)
            expect(not is_ssrf_refusal(msg_n), "scoping the target lifts the SSRF block (refusal is no longer the guard)", msg_n[:200])
            if os.environ.get("AITM_OBSCURA") == "1":
                fail(f"AITM_OBSCURA=1 but the scoped navigation did not complete: {msg_n[:200]}")
            expect(any(h in msg_n.lower() for h in NO_BROWSER_HINTS),
                   "the lifted navigation reached the engine (no obscura present to finish the load)", msg_n[:200])
    finally:
        # restore scope: drop anything we added back to the original set
        if op is not None:
            try:
                now = set(scope_names(op.call("scope.list")))
                for e in now - set(orig):
                    confirm_call(op, "scope.remove", {"host": e})
            except Exception:  # noqa: BLE001
                pass
        for b in (agent, op):
            if b:
                b.close()
        if core:
            core.stop()
        tgt.stop()

    if _failures:
        fail(f"{len(_failures)} expectation(s) failed: " + "; ".join(_failures[:6]))
    ok("PASS: the SSRF/private-network guard blocked the out-of-scope loopback navigation, and an exact scope entry lifted it")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
