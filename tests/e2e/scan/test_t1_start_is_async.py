#!/usr/bin/env python3
# e2e: tier=T1 surface=scan needs=http
"""T1-1: `scan.start` is asynchronous — it returns a job id within 2 s with the
job still `queued|running`, and the SAME connection can poll `scan.status`
concurrently without blocking, until the job reaches `done`.

Observers (never the verb's own word for it):
  - the wall clock, measured with `time.monotonic()` around each call;
  - the target's own control log (`V.logs.scanner_requests(seq0)`), which proves
    the job really drove traffic at the origin rather than returning early and
    doing nothing.

This cell proves the LOOPBACK half of parent AC T1-1 ("stdio and loopback"); the
harness has no stdio MCP client, so the stdio half is T1b's Rust test (child spec
D8). SKIPs 77 when the live core does not advertise `scan.start` / `scan.status`
(the T1b engine is not on this build).
"""
import sys
import tempfile
import time
from pathlib import Path

E2E = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(E2E))

from aitm_e2e import check, fail, free_port, ok, section  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.scan import ScanTarget, scan_call, start_job, require_verbs, wait_terminal  # noqa: E402

# Literal budgets of AC T1-1 / plan task B5.
START_BUDGET_S = 2.0
STATUS_BUDGET_S = 2.0
POLL_WINDOW_S = 5.0
POLL_GAP_S = 0.2
TERMINAL_TIMEOUT_S = 600.0


def main() -> None:
    with ScanTarget("vulnerable") as v:
        findings_dir = tempfile.mkdtemp(prefix="aitm-e2e-scan-t1-async-")
        cfg = CoreConfig(
            proxy_port=free_port(),
            scope_entries=[v.authority],
            findings_dir=findings_dir,
        )
        with Aitm.server(cfg) as core:
            op = BusClient.operator(core)
            require_verbs(op, "scan.start", "scan.status")

            seq0 = v.logs.reset()

            section("scan.start returns a job id within 2 s, not a finished scan")
            t0 = time.monotonic()
            started = start_job(op, "operator", target=v.base)
            start_s = time.monotonic() - t0
            check(start_s < START_BUDGET_S,
                  f"scan.start returned in {start_s:.3f}s (< {START_BUDGET_S}s)")
            job = started.get("job")
            check(isinstance(job, str) and job.startswith("scan-"),
                  f"scan.start job id is a scan- id: {job!r}")
            state0 = (started.get("status") or {}).get("state")
            check(state0 in {"queued", "running"},
                  f"scan.start status.state is queued|running, got {state0!r}")

            section("the same connection polls scan.status while the job runs")
            samples: list[tuple[str, float]] = []
            deadline = time.monotonic() + POLL_WINDOW_S
            while True:
                t = time.monotonic()
                st = scan_call(op, "operator", "scan.status", {"job": job})
                d = time.monotonic() - t
                state = st.get("state") if isinstance(st, dict) else None
                samples.append((state, d))
                if state == "done" or time.monotonic() >= deadline:
                    break
                time.sleep(POLL_GAP_S)

            running = [(s, d) for s, d in samples if s != "done"]
            check(bool(running),
                  f"at least one scan.status answered while state != done "
                  f"(states seen: {[s for s, _ in samples]})")
            slow = [(s, d) for s, d in running if d >= STATUS_BUDGET_S]
            check(not slow,
                  f"every scan.status on the starting connection answered in "
                  f"< {STATUS_BUDGET_S}s while the job was not done "
                  f"(max {max((d for _, d in running), default=0.0):.3f}s, slow: {slow})")

            section("the job reaches done on its own")
            try:
                final = wait_terminal(op, "operator", job, timeout=TERMINAL_TIMEOUT_S)
            except TimeoutError as e:
                fail(str(e))
                return
            check(final.get("state") == "done",
                  f"job reached state done (got {final.get('state')!r}, "
                  f"stopped_reason={final.get('stopped_reason')!r})")

            section("the target's own log proves the job drove real traffic")
            reqs = v.logs.scanner_requests(seq0)
            check(len(reqs) > 0,
                  f"the target recorded {len(reqs)} scanner request(s) after seq {seq0}")

            ok("loopback half of T1-1 proven; the stdio half is T1b's Rust test "
               "(the harness has no stdio MCP client)")
            op.close()


if __name__ == "__main__":
    main()
