#!/usr/bin/env python3
# e2e: tier=T1 surface=mcp
"""mcp/test_tool_list_complete -- the MCP tool list advertises the FULL current tool
surface (no stale hardcoded count), and EVERY advertised tool is really wired:
callable or correctly gated, never a phantom list entry.

Anti-drift cell for the bus surface -- the failure that rotted the old live selftest
(a tools/list frozen at a hardcoded count while the registry moved on, or a name in
the list that no longer resolves). Everything is GROUND TRUTH, never a frozen number:

  COMPLETE  the expected set is DERIVED at runtime from the maintained Rust contract
            EXPECTED_TOOLS (crates/aitm/tests/frontends.rs, kept honest against the
            real registry by `cargo test` ac7_exact_tool_set). The live tools/list
            over the bus must advertise every one; the count is len(parsed list),
            never a literal here. Opt-in extras (l4.*, plugins) are reported, not failed.
  WIRED     every advertised tool is CALLED over the real bus as the agent (empty
            args). The server `unknown tool` error (a name dispatch cannot resolve =
            a phantom advertisement) and a `no core services` internal error (an
            unwired handler) must never happen; every tool must instead run, be
            refused by the agent policy gate, or reject empty args at schema coercion.
  GATED     positive controls: a Read tool (proxy.status) is callable by the agent
            and reflects the live core; a Sensitive tool (proxy.pause) is refused.
  REAL FLOW one real request is driven through the real proxy and flow.list is
            asserted to return the id of the flow the core actually captured.

Boots its OWN real core (Aitm.server) + echo-record upstream on dedicated free ports
(the aitm_e2e convention; converted from the legacy _lib/mcp harness). Driven as the
agent (reads only) + the operator for the role-parity check; nothing global mutated.
Soft-assertion battery: every failed expectation prints, the run continues and cleans
up, exit 1 iff anything failed. Exit 0 pass / 1 fail / 77 skip.
"""
from __future__ import annotations

import re
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import fail, free_port, ok, repo_root, section  # noqa: E402
from aitm_e2e.bus import BusClient, BusError, ToolError  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.proxyutil import via_proxy  # noqa: E402
from aitm_e2e.upstream import Upstream  # noqa: E402

CONTRACT = Path(repo_root()) / "crates" / "aitm" / "tests" / "frontends.rs"


def parse_expected_tools(path: Path):
    """The source-of-truth tool set from the Rust EXPECTED_TOOLS contract. Returns
    (declared_len, [names]); declared_len is the [&str; N] annotation (or None). The
    count the test uses is len(names) -- derived from the list, never hardcoded."""
    text = path.read_text(encoding="utf-8")
    strict = re.search(r"EXPECTED_TOOLS\s*:\s*\[\s*&str\s*;\s*(\d+)\s*\]\s*=\s*\[(.*?)\];", text, re.S)
    if strict:
        declared, body = int(strict.group(1)), strict.group(2)
    else:
        loose = re.search(r"EXPECTED_TOOLS[^=]*=\s*\[(.*?)\];", text, re.S)
        if not loose:
            return None, []
        declared, body = None, loose.group(1)
    body = re.sub(r"//[^\n]*", "", body)  # drop line comments before harvesting literals
    return declared, re.findall(r'"([^"]+)"', body)


def classify(bus: BusClient, name: str):
    """Call `name` as the agent with empty args; bucket the GROUND-TRUTH outcome.
    unknown/no-services are wiring BUGS; gated/callable/dispatched are all 'wired'."""
    try:
        status, res = bus.try_call(name, {})
    except (ToolError, BusError) as e:
        status, res = "error", str(e)
    if status == "ok":
        return "callable", ""
    msg = str(res)
    low = msg.lower()
    if "unknown tool" in low:
        return "unknown", msg
    if "no core services" in low or "with_services" in low:
        return "no-services", msg
    if "refused" in low:
        return "gated", msg
    return "dispatched", msg


def wait_for_flow(bus: BusClient, pred, timeout: float = 15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        for row in bus.call("flow.table").get("flows", []):
            if pred(row):
                return row
        time.sleep(0.15)
    return None


def main() -> int:
    if not CONTRACT.exists():
        fail(f"source-of-truth contract not found: {CONTRACT} (cannot derive the expected surface)")

    up = Upstream().start()
    core = agent = op = None
    failures: list[str] = []

    def expect(cond, msg: str, detail="") -> bool:
        if cond:
            ok(msg)
            return True
        line = f"  [FAIL] {msg}"
        if detail != "":
            line += f"   -- {str(detail)[:200]}"
        print(line, flush=True)
        failures.append(msg)
        return False

    try:
        section("boot: real aitm core + echo-record upstream; attach as the agent")
        cfg = CoreConfig(proxy_port=free_port(), browser_proxy_port=free_port(),
                         scope_entries=[up.authority, "127.0.0.1"])
        core = Aitm.server(cfg)
        agent = BusClient.agent(core)

        section("COMPLETE: the live tools/list matches the maintained EXPECTED_TOOLS contract")
        live_tools = agent.tools()
        live_names = [t.get("name") for t in live_tools if isinstance(t, dict) and t.get("name")]
        live = set(live_names)
        expect(len(live) > 0, "the live core advertises a non-empty tool surface (tools/list over the real bus)", len(live))
        expect(len(live) == len(live_names), "tools/list advertises no duplicate names",
               sorted(n for n in live_names if live_names.count(n) > 1))
        declared, expected_list = parse_expected_tools(CONTRACT)
        expected = set(expected_list)
        expect(len(expected) > 0, "parsed the EXPECTED_TOOLS contract (the maintained source of truth)",
               f"{len(expected)} names from {CONTRACT.name}")
        if declared is not None:
            expect(declared == len(expected_list), "the contract's [&str; N] length matches its own list (self-consistent)",
                   (declared, len(expected_list)))
        missing = sorted(expected - live)
        extra = sorted(live - expected)
        expect(not missing, "every tool in the maintained contract is advertised live (no stale/truncated surface)", missing)
        expect(len(live) >= len(expected), f"the live count ({len(live)}) >= the derived contract count ({len(expected)}); no stale literal",
               (len(live), len(expected)))
        print(f"note: live={len(live)} contract={len(expected)} extras(opt-in)={extra or 'none'}", flush=True)

        bad = [t["name"] for t in live_tools if isinstance(t, dict) and t.get("name")
               and not (isinstance(t.get("inputSchema"), dict) and t["inputSchema"])]
        expect(not bad, "every advertised tool exposes a non-empty inputSchema (no malformed registration)", bad)

        section("WIRED: every advertised tool is callable OR correctly gated, none phantom")
        buckets: dict[str, list[str]] = {k: [] for k in ("callable", "gated", "dispatched", "unknown", "no-services")}
        details: dict[str, str] = {}
        for name in sorted(live):
            kind, msg = classify(agent, name)
            buckets[kind].append(name)
            if msg:
                details[name] = msg
        expect(not buckets["unknown"], "NO advertised tool answers `unknown tool` -- every name resolves in the registry",
               {n: details.get(n, "")[:100] for n in buckets["unknown"]})
        expect(not buckets["no-services"], "NO advertised tool reports missing core services -- every handler is wired",
               {n: details.get(n, "")[:100] for n in buckets["no-services"]})
        wired = len(buckets["callable"]) + len(buckets["gated"]) + len(buckets["dispatched"])
        expect(wired == len(live), "every advertised tool dispatched (callable or correctly gated), none phantom",
               {"wired": wired, "total": len(live), "phantom": buckets["unknown"] + buckets["no-services"]})
        print(f"note: of {len(live)} advertised -- callable={len(buckets['callable'])} "
              f"gated={len(buckets['gated'])} needs-args/err={len(buckets['dispatched'])}", flush=True)

        section("GATED: positive controls (a Read is callable, a Sensitive is refused)")
        if "proxy.status" in live:
            st, status = agent.try_call("proxy.status", {})
            expect(st == "ok" and isinstance(status, dict) and "listening" in status,
                   "a Read tool (proxy.status) is callable by the agent and reflects the live core", status)
        if "proxy.pause" in live:
            expect("proxy.pause" in buckets["gated"],
                   "a Sensitive tool (proxy.pause) is correctly GATED for the agent",
                   f"bucket={next((k for k, v in buckets.items() if 'proxy.pause' in v), '?')}: {details.get('proxy.pause', '')[:140]}")

        section("REAL FLOW: a real request rides the proxy and flow.list carries its id")
        if "flow.list" in live:
            tag = f"toollist-{uuid.uuid4().hex[:8]}"
            resp = via_proxy(cfg.proxy_port, "GET", f"{up.base}/?e2e-toollist={tag}")
            expect(resp.status == 200, "a real request rode the real proxy and got a response", resp.status)
            row = wait_for_flow(agent, lambda f: tag in (f.get("path") or ""))
            expect(row is not None, "flow.list is callable and the core captured our REAL flow (ground truth)",
                   "no flow carrying our marker within 15s")
            if row is not None:
                st, flows = agent.try_call("flow.list", {})
                expect(st == "ok" and isinstance(flows, list) and row.get("id") in flows,
                       "flow.list returns the id of the flow the core actually captured",
                       {"captured_id": row.get("id"), "ok": st, "count": len(flows) if isinstance(flows, list) else flows})

        section("role parity: the operator sees the IDENTICAL advertised surface")
        op = BusClient.operator(core)
        op_live = {t.get("name") for t in op.tools() if isinstance(t, dict) and t.get("name")}
        expect(op_live == live, "the advertised tool list is identical for operator and agent (role-independent)",
               {"agent-only": sorted(live - op_live), "operator-only": sorted(op_live - live)})
    finally:
        for b in (agent, op):
            if b:
                b.close()
        if core:
            core.stop()
        up.stop()

    if failures:
        fail(f"{len(failures)} expectation(s) failed: " + "; ".join(failures[:6]))
    ok("PASS: the advertised tool surface is complete (live == contract) and every tool is wired, over the real bus")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
