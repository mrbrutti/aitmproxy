#!/usr/bin/env python3
# e2e: tier=T1 surface=scan needs=http
"""scan/test_t1_lane_skip -- AC T1-11: an unavailable lane is skipped, not fatal.

`dead` = the first of `[ws, l4_stream, l4_packet]` that NO `scan.checks` entry lists
(spec D8 / plan P6: there is no verb to disable a lane, so the cell SKIPs 77 when
every lane is live and the AC is then held by T1b's unit test). An inline profile
naming `[http, dead]` starts, runs `http`, and both the `scan.start` result and
`scan.status` report `lanes.skipped == [{"lane": dead, "reason": <non-empty>}]`,
`lanes.run == ["http"]`. A profile naming only `[dead]` is refused with
`lane_unavailable` and NO request reaches the target.

The core boots with `l4_enabled=True` so an `l4_*` dead lane is reported as
`lane_unavailable` and not pre-empted by `refused_l4` (spec D3 order). Profiles
with an L4 lane take the operator confirm handshake (`confirm=True`).

Observer: the target's own control log (zero requests after the refusal; requests
present for the http run). Own target + own core; tokens never printed.

SKIP 77: `aitm-testtarget-serve` not built; the v2 verbs absent; every lane live.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.scan import (  # noqa: E402
    boot_target,
    require_verbs,
    scan_call,
    scan_error_code,
    scan_try,
    start_job,
    wait_terminal,
)

CANDIDATES = ("ws", "l4_stream", "l4_packet")
# A tiny inline profile (40 probes) on one origin: 300 s is generous for it.
JOB_TIMEOUT = 300.0


def inline_profile(name: str, origin: str, lanes: list[str]) -> dict:
    """A minimal valid ScanProfile (every other field is `#[serde(default)]`); a
    small budget keeps the http run short."""
    return {
        "name": name,
        "target": {"origins": [origin]},
        "lanes": lanes,
        "budget": {"probes": 40, "time_s": 120},
    }


def main() -> int:
    target = core = op = None
    try:
        section("arrange: vulnerable target + own core (l4 layer enabled)")
        target = boot_target("vulnerable")
        cfg = CoreConfig(proxy_port=free_port(), browser_proxy_port=free_port(),
                         scope_entries=[target.authority], l4_enabled=True)
        core = Aitm.server(cfg)
        op = BusClient.operator(core)
        require_verbs(op, "scan.start", "scan.status", "scan.checks")

        section("pick the dead lane from scan.checks")
        checks = scan_call(op, "operator", "scan.checks", {}).get("checks", [])
        avail = {ln for c in checks if isinstance(c, dict) for ln in (c.get("lanes") or [])}
        dead = next((ln for ln in CANDIDATES if ln not in avail), None)
        print(f"note: lanes with checks on this build = {sorted(avail)}; dead = {dead!r}", flush=True)
        if dead is None:
            skip("every lane is live on this build; lane skip cannot be provoked")
        needs_confirm = dead.startswith("l4_")
        seq0 = target.logs.reset()

        section(f"[http, {dead}]: starts, runs http, reports the skipped lane")
        r = start_job(op, "operator", profile=inline_profile("e2e-skip", target.base, ["http", dead]),
                      confirm=needs_confirm)
        job = r["job"]
        lanes = r.get("lanes") or {}
        skipped = lanes.get("skipped")
        check(isinstance(skipped, list) and len(skipped) == 1, f"scan.start lanes.skipped has one entry (got {skipped!r})")
        entry = skipped[0] if isinstance(skipped, list) and skipped else {}
        reason = entry.get("reason") if isinstance(entry, dict) else None
        check(isinstance(entry, dict) and entry.get("lane") == dead,
              f"lanes.skipped[0].lane == {dead!r} (got {entry!r})")
        check(isinstance(reason, str) and reason.strip() != "", f"lanes.skipped[0].reason is non-empty ({reason!r})")
        check(skipped == [{"lane": dead, "reason": reason}], "lanes.skipped == [{lane: dead, reason}] exactly")
        check(lanes.get("run") == ["http"], f"lanes.run == ['http'] (got {lanes.get('run')!r})")
        check(lanes.get("requested") == ["http", dead], f"lanes.requested == ['http', {dead!r}] (got {lanes.get('requested')!r})")
        st = scan_call(op, "operator", "scan.status", {"job": job})
        check((st.get("lanes") or {}).get("skipped") == skipped, "scan.status reports the same lanes.skipped")
        check((st.get("lanes") or {}).get("run") == ["http"], "scan.status reports lanes.run == ['http']")
        final = wait_terminal(op, "operator", job, timeout=JOB_TIMEOUT)
        check(final.get("state") == "done", f"the http-only job finished done (got {final.get('state')!r}, "
              f"stopped_reason={final.get('stopped_reason')!r})")
        by_lane = (final.get("probes") or {}).get("by_lane") or {}
        check(dead not in by_lane, f"no probes charged to the dead lane (by_lane={by_lane})")
        n_http = len(target.logs.scanner_requests(seq0))
        check(n_http > 0, f"the http lane really hit the target ({n_http} request(s) in the control log)")

        section(f"[{dead}] alone: lane_unavailable, nothing reaches the target")
        seq1 = target.logs.reset()
        args = {"profile": inline_profile("e2e-dead", target.base, [dead])}
        # confirm=True: an L4 dead lane is confirmable, and the refusal has to survive
        # the confirmation rather than hide behind the prompt.
        status, payload = scan_try(op, "operator", "scan.start", args, confirm=needs_confirm)
        check(status == "error", f"scan.start with only [{dead}] is refused (got {status!r}: {str(payload)[:120]})")
        code = scan_error_code(str(payload)) if status == "error" else None
        check(code == "lane_unavailable", f"refusal code == lane_unavailable (got {code!r})")
        check(target.logs.scanner_requests(seq1) == [], "no request reached the target after the refusal")
        ok(f"PASS: lane {dead} skipped with a reason alongside http; alone it is lane_unavailable with zero traffic")
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
