#!/usr/bin/env python3
# e2e: tier=T1 surface=scan needs=http
"""scan/test_t1_contract -- AC T1-8: live `tools/list` equals the maintained contract.

`expected_scan_verbs(op)` parses the `scan.*` names of the Rust EXPECTED_TOOLS list
(`crates/aitm/tests/frontends.rs`) and raises `ContractDrift` unless the live
`tools/list` of a REAL core advertises exactly that set. Every live `scan.*` tool
exposes a non-empty `inputSchema`. The legacy trio runs for real at operator so the
verb ledger covers it: `scan.passive {}` -> a dict with `findings`; `scan.report {}`
-> a dict with `report_md` (`issues_md` noted when present, spec D3); `scan.discover
{target: V.base, max_pages: 2}` -> a dict with `pages_crawled <= 2`. When the v2 verbs
are present, every D3 verb must be in the contract AND live.

Observers: the live `tools/list` over the real bus reconciled against the Rust
contract file on disk; the target's own control log for `scan.discover`.

The legacy trio exists on today's `main` and always runs here. The cell SKIPs 77 at
the END (`missing verb scan.start`) when the v2 verb family is not on the build, so
the D3-completeness half of T1-8 is never reported green by a legacy-only core.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.proxyutil import via_proxy  # noqa: E402
from aitm_e2e.scan import (  # noqa: E402
    ContractDrift,
    SCAN_VERBS_D3,
    boot_target,
    expected_scan_verbs,
    scan_call,
    scan_tools,
)

LEGACY_TRIO = ("scan.discover", "scan.passive", "scan.report")


def main() -> int:
    target = core = op = None
    try:
        section("arrange: vulnerable target + own core on free ports")
        target = boot_target("vulnerable")
        cfg = CoreConfig(proxy_port=free_port(), browser_proxy_port=free_port(),
                         scope_entries=[target.authority])
        core = Aitm.server(cfg)
        op = BusClient.operator(core)

        section("CONTRACT: live scan.* tools == EXPECTED_TOOLS scan.* entries")
        try:
            verbs = expected_scan_verbs(op)
        except ContractDrift as e:
            fail(f"ContractDrift: {e}")
        live = scan_tools(op)
        check(len(verbs) > 0, f"parsed {len(verbs)} scan.* verb(s) from the Rust contract")
        check(live == set(verbs), f"live scan.* set equals the contract ({len(live)} verb(s))")
        check(set(LEGACY_TRIO) <= set(verbs), "the legacy trio scan.discover/passive/report is in the contract")
        check(set(LEGACY_TRIO) <= live, "the legacy trio is advertised live")

        section("SCHEMA: every live scan.* tool has a non-empty inputSchema")
        tools = op.tools()
        bad = sorted(t.get("name") for t in tools
                     if isinstance(t, dict) and str(t.get("name", "")).startswith("scan.")
                     and not (isinstance(t.get("inputSchema"), dict) and t["inputSchema"]))
        check(not bad, f"every live scan.* tool exposes a non-empty inputSchema (bad: {bad})")

        section("LEGACY TRIO at operator (runs on today's main; ledger coverage)")
        resp = via_proxy(cfg.proxy_port, "GET", f"{target.base}/")
        check(resp.status == 200, f"one real request rode the proxy to V (status {resp.status}) so passive has a flow")
        passive = scan_call(op, "operator", "scan.passive", {})
        check(isinstance(passive, dict) and isinstance(passive.get("findings"), list),
              f"scan.passive {{}} -> a dict with a `findings` list ({len(passive.get('findings', [])) if isinstance(passive, dict) else '?'} finding(s))")
        report = scan_call(op, "operator", "scan.report", {})
        check(isinstance(report, dict) and isinstance(report.get("report_md"), str),
              "scan.report {} -> a dict with `report_md`")
        print(f"note: scan.report issues_md {'present' if isinstance(report, dict) and 'issues_md' in report else 'absent'} "
              "(spec D3: added by the v2 engine)", flush=True)
        seq0 = target.logs.reset()
        disc = scan_call(op, "operator", "scan.discover", {"target": target.base, "max_pages": 2})
        check(isinstance(disc, dict), "scan.discover {target, max_pages: 2} -> a dict")
        pages = disc.get("pages_crawled") if isinstance(disc, dict) else None
        check(isinstance(pages, int) and 0 <= pages <= 2,
              f"scan.discover is bounded by max_pages: pages_crawled == {pages!r} <= 2")
        check(isinstance(disc.get("endpoints"), list) and isinstance(disc.get("injection_points"), list),
              "scan.discover result keeps its `endpoints` and `injection_points` lists (D3: shape unchanged)")
        n_target = len(target.logs.scanner_requests(seq0))
        print(f"note: scan.discover produced {n_target} request(s) at the target (0 = store-only fallback, no browser)",
              flush=True)

        section("D3 COMPLETENESS (v2 verbs)")
        if "scan.start" not in live:
            skip("missing verb scan.start: contract equality + legacy trio verified; "
                 "D3 verb completeness is not provable on this build")
        missing_contract = sorted(set(SCAN_VERBS_D3) - set(verbs))
        missing_live = sorted(set(SCAN_VERBS_D3) - live)
        check(not missing_contract, f"every D3 verb is in EXPECTED_TOOLS (missing: {missing_contract})")
        check(not missing_live, f"every D3 verb is advertised live (missing: {missing_live})")
        ok("PASS: live tools/list == contract for scan.*, every D3 verb present, legacy trio ran")
        return 0
    finally:
        if op:
            op.close()
        if core:
            core.stop()
        if target:
            target.stop()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
