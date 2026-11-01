#!/usr/bin/env python3
# e2e: tier=T1 surface=scan needs=http
"""T1-5: scope and budget are enforced BEFORE and DURING the job, and both are
proven at the origin rather than from the scanner's own counters.

  - A `scan.start` naming the patched target P, whose authority is deliberately
    NOT in the core's scope, fails with the D3 code `out_of_scope`, and P's own
    control log holds zero requests: the refusal happened before any socket.
  - A `scan.start` on the in-scope vulnerable target V with
    `overrides={"budget": {"probes": 50}}` stops with `stopped_reason: "budget"`,
    `probes.sent <= 50`, and V's own log counts at most 50 requests for the job.

Observers: BOTH targets' control logs (`TargetLogs.scanner_requests`).

SKIPs 77 when the live core lacks `scan.start` / `scan.status`.
"""
import os
import shutil
import sys
import tempfile
from pathlib import Path

E2E = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(E2E))

from aitm_e2e import check, fail, free_port, section  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.scan import (  # noqa: E402
    boot_target,
    require_verbs,
    scan_error_code,
    scan_try,
    start_job,
    wait_terminal,
)

PROBE_BUDGET = 50
JOB_TIMEOUT = 600.0


def main() -> None:
    work = tempfile.mkdtemp(prefix="aitm-e2e-scan-t1-scope-")
    try:
        with boot_target("vulnerable") as v, boot_target("patched") as p:
            findings_dir = os.path.join(work, "findings")
            # Only V is in scope. P is booted and reachable, but out of scope.
            cfg = CoreConfig(
                proxy_port=free_port(),
                scope_entries=[v.authority],
                findings_dir=findings_dir,
            )
            with Aitm.server(cfg) as core:
                op = BusClient.operator(core)
                require_verbs(op, "scan.start", "scan.status")

                section("an out-of-scope origin is refused before any socket is opened")
                status, payload = scan_try(op, "operator", "scan.start", {"target": p.base})
                check(status == "error",
                      f"scan.start on the out-of-scope origin was refused "
                      f"(got {status!r}: {payload!r})")
                code = scan_error_code(str(payload))
                check(code == "out_of_scope",
                      f"the refusal carries the D3 code out_of_scope, got {code!r} "
                      f"from {payload!r}")
                p_reqs = p.logs.scanner_requests(0)
                check(p_reqs == [],
                      f"the out-of-scope target recorded zero requests "
                      f"(its own log holds {len(p_reqs)})")

                section(f"an in-scope job with budget.probes = {PROBE_BUDGET} stops on budget")
                seq0 = v.logs.reset()
                job = start_job(op, "operator", target=v.base,
                                overrides={"budget": {"probes": PROBE_BUDGET}})["job"]
                try:
                    final = wait_terminal(op, "operator", job, timeout=JOB_TIMEOUT)
                except TimeoutError as e:
                    fail(str(e))
                check(final.get("stopped_reason") == "budget",
                      f"stopped_reason is budget, got {final.get('stopped_reason')!r} "
                      f"(state={final.get('state')!r})")
                sent = (final.get("probes") or {}).get("sent")
                check(isinstance(sent, int) and sent <= PROBE_BUDGET,
                      f"probes.sent ({sent!r}) <= the requested budget {PROBE_BUDGET}")

                v_reqs = v.logs.scanner_requests(seq0)
                check(len(v_reqs) <= PROBE_BUDGET,
                      f"the target's own log counts {len(v_reqs)} request(s) for the job "
                      f"(<= {PROBE_BUDGET})")
                op.close()
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
