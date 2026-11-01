#!/usr/bin/env python3
# e2e: tier=T1 surface=surface
"""Anti-drift: the live tool surface matches the SOURCE OF TRUTH, and gating is real.

This is the cell that would have caught the exact drift that killed
apps/web/scripts/selftest-live.mjs: a frozen 37-tool list, the wrong token under
policy, and absence-assertions that rot. Instead we DERIVE the expected set from
the Rust EXPECTED_TOOLS contract at runtime (never a hardcoded count), confirm the
live core registers every one with a real inputSchema, and assert the operator vs
agent asymmetry directly.
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, repo_root, section  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402

CONTRACT = Path(repo_root()) / "crates" / "aitm" / "tests" / "frontends.rs"


def parse_expected_tools(path: Path) -> list[str]:
    """Extract the EXPECTED_TOOLS string literals from the Rust contract, ignoring
    comments. The single source of truth the coders already maintain."""
    text = path.read_text(encoding="utf-8")
    m = re.search(r"EXPECTED_TOOLS[^=]*=\s*\[(.*?)\];", text, re.S)
    if not m:
        fail(f"could not find EXPECTED_TOOLS in {path}")
    body = re.sub(r"//[^\n]*", "", m.group(1))  # strip line comments
    return re.findall(r'"([^"]+)"', body)


def main() -> int:
    if not CONTRACT.exists():
        fail(f"contract source not found: {CONTRACT}")
    expected = set(parse_expected_tools(CONTRACT))
    ok(f"parsed {len(expected)} tools from the Rust EXPECTED_TOOLS contract (no hardcoded count)")

    cfg = CoreConfig(proxy_port=free_port())
    core = Aitm.server(cfg)
    bus = None
    op = None
    try:
        section("live surface reconciles against the source of truth")
        bus = BusClient.agent(core)
        tools = bus.tools()
        live = {t["name"] for t in tools}
        missing = sorted(expected - live)
        extra = sorted(live - expected)
        check(not missing, f"every contract tool is registered live (missing: {missing})")
        ok(f"live={len(live)} contract={len(expected)}; extras not in contract: {extra or 'none'}")

        section("every live tool has a real inputSchema (no malformed registration)")
        bad = [t["name"] for t in tools if not (isinstance(t.get("inputSchema"), dict) and t.get("inputSchema"))]
        check(not bad, f"every tool exposes a non-empty inputSchema (bad: {bad})")

        section("role asymmetry: a Sensitive command is refused for agent, allowed for operator")
        st_agent, msg = bus.try_call("proxy.pause")
        check(st_agent == "error",
              f"agent is REFUSED proxy.pause under the default Auto policy (got {st_agent}: {msg[:80]})")
        try:
            op = BusClient.operator(core)
        except Exception as e:  # noqa: BLE001
            op = None
            ok(f"operator-over-loopback not available here ({type(e).__name__}); operator side not asserted")
        if op:
            st_op, _ = op.try_call("proxy.pause")
            check(st_op == "ok", f"operator is ALLOWED proxy.pause (got {st_op})")
            op.try_call("proxy.resume")  # restore state
    finally:
        if op:
            op.close()
        if bus:
            bus.close()
        core.stop()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
