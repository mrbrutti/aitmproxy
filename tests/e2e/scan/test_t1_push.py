#!/usr/bin/env python3
# e2e: tier=T1 surface=scan needs=http
"""T1-3: a SECOND operator connection that holds a `flow.subscribe` subscription
receives the job's `notifications/aitm/job` push lines — `started`, at least one
`progress`, at least one `issue` (the target is vulnerable, so a scan finds one)
and `finished` — with strictly increasing `seq` and the engine's coalescing rule
honoured: no more than 4 `progress` lines in any one-second window of `ts_ms`
(parent spec D3 "Progress push").

Observer: the independent subscriber connection. The connection that STARTS the
job is a different `BusClient`, so the lines prove real fan-out (D3: lines go to
every connection holding a flow subscription), not an echo to the caller.

SKIPs 77 when the live core lacks `scan.start` / `scan.status`.
"""
import sys
import tempfile
from pathlib import Path

E2E = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(E2E))

from aitm_e2e import check, free_port, ok, section  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.scan import (  # noqa: E402
    ScanTarget,
    collect_push,
    require_verbs,
    start_job,
    subscribe,
)

# Literals of AC T1-3 / parent spec D3.
REQUIRED_EVENTS = {"started", "progress", "issue", "finished"}
MAX_PROGRESS_PER_WINDOW = 4
WINDOW_MS = 1000
PUSH_TIMEOUT_S = 600.0


def max_progress_in_any_window(progress_ts: list[int]) -> tuple[int, int | None]:
    """The largest number of `progress` lines inside any `WINDOW_MS` window of
    `ts_ms`, and the window start that produced it. Each line's own `ts_ms` opens
    a window `[ts, ts + WINDOW_MS)`; that covers every window that can be maximal."""
    worst = 0
    at: int | None = None
    for start in progress_ts:
        n = sum(1 for t in progress_ts if start <= t < start + WINDOW_MS)
        if n > worst:
            worst, at = n, start
    return worst, at


def main() -> None:
    with ScanTarget("vulnerable") as v:
        findings_dir = tempfile.mkdtemp(prefix="aitm-e2e-scan-t1-push-")
        cfg = CoreConfig(
            proxy_port=free_port(),
            scope_entries=[v.authority],
            findings_dir=findings_dir,
        )
        with Aitm.server(cfg) as core:
            op = BusClient.operator(core)
            require_verbs(op, "scan.start", "scan.status")

            section("a second operator connection subscribes before the job starts")
            sub = subscribe(BusClient.operator(core))
            ok("second operator BusClient holds a flow.subscribe subscription")

            v.logs.reset()
            job = start_job(op, "operator", target=v.base)["job"]
            ok(f"started {job} on the FIRST connection")

            section("drain the job's push lines from the subscriber")
            lines = collect_push(sub, job, timeout=PUSH_TIMEOUT_S)
            check(len(lines) > 0,
                  f"the subscriber received {len(lines)} notifications/aitm/job line(s)")
            if not lines:
                return

            events = [ln.get("event") for ln in lines]
            check(REQUIRED_EVENTS.issubset(set(events)),
                  f"events include {sorted(REQUIRED_EVENTS)} "
                  f"(missing {sorted(REQUIRED_EVENTS - set(events))}; saw {events})")
            check(events[-1] == "finished",
                  f"the last line of the job is `finished`, got {events[-1]!r}")

            section("every line carries the D3 shape")
            bad_kind = [ln.get("kind") for ln in lines if ln.get("kind") != "scan"]
            check(not bad_kind, f"every line has kind == 'scan' (offenders: {bad_kind})")
            bad_job = [ln.get("job") for ln in lines if ln.get("job") != job]
            check(not bad_job, f"every line names job {job} (offenders: {bad_job})")
            no_state = [ln.get("event") for ln in lines
                        if not isinstance(ln.get("status"), dict)
                        or not isinstance((ln.get("status") or {}).get("state"), str)]
            check(not no_state,
                  f"every line carries status.state (events missing it: {no_state})")
            issue_lines = [ln for ln in lines if ln.get("event") == "issue"]
            check(all(isinstance(ln.get("issue"), dict) for ln in issue_lines),
                  f"every `issue` line carries an `issue` object ({len(issue_lines)} line(s))")

            section("seq is strictly increasing")
            seqs = [ln.get("seq") for ln in lines]
            check(all(isinstance(s, int) for s in seqs),
                  f"every seq is an integer: {seqs}")
            breaks = [(seqs[i], seqs[i + 1]) for i in range(len(seqs) - 1)
                      if not (isinstance(seqs[i], int) and isinstance(seqs[i + 1], int)
                              and seqs[i + 1] > seqs[i])]
            check(not breaks,
                  f"seq is strictly increasing across {len(seqs)} line(s) "
                  f"(non-increasing pairs: {breaks})")

            section("progress lines are coalesced to at most 4 per second")
            progress_ts = [ln.get("ts_ms") for ln in lines if ln.get("event") == "progress"]
            check(all(isinstance(t, int) for t in progress_ts),
                  f"every progress line has an integer ts_ms ({len(progress_ts)} line(s))")
            worst, at = max_progress_in_any_window([t for t in progress_ts if isinstance(t, int)])
            check(worst <= MAX_PROGRESS_PER_WINDOW,
                  f"at most {MAX_PROGRESS_PER_WINDOW} progress lines in any {WINDOW_MS} ms "
                  f"window of ts_ms (worst was {worst} starting at ts_ms={at})")
            sub.close()
            op.close()


if __name__ == "__main__":
    main()
