#!/usr/bin/env python3
# e2e: tier=T1 surface=scan needs=l4
"""scan/t6_dns_udp -- AC T6-2: the DNS grammar's label-length mutation trips the
seeded UDP parser fault on V and nothing on P.

The UDP half of the stream lane (parent D8.5: the lane's transport is a plain
`UdpSocket`, authorised per datagram by `L4Guard::check(Inject, ...)`; it needs
no capture privilege). The target is the REAL seeded speaker `l4-dns-fault`
(child spec D5): a benign A query for `example.test` is answered with one
answer record, a query for `.` is the liveness probe, and a label length byte
that runs past the end of the datagram is the V trigger -- the driver then
DROPS EVERY DATAGRAM for the 5 s crash window and logs it. P answers FORMERR
(`<id> 81 81`, zero counts) and stays up.

What is proven:

  * the job (built-in `l4-stream-safe`, `overrides.target.l4` naming the UDP
    endpoint and grammar `dns`) reaches a terminal `done`;
  * at least one issue whose class is `l4-parser-fault` or `l4-crash` (the
    oracle decides which: a reproducible protocol-error-with-reset is the
    fault, silence plus two failed liveness probes is the crash) and whose
    `location.l4.grammar` is `dns`, on the UDP endpoint;
  * the INDEPENDENT observer: the speaker's own `/log/l4` `downtime` ring for
    `l4-dns-fault` is non-empty, and its inbound `messages` include at least
    one classified `ok` (the generated queries really parse as DNS);
  * on the PATCHED target the same job files zero issues.

Observer: the seeded speaker's control-origin L4 log.

SKIPs 77: missing `scan.*` verbs; no `l4_stream` check in `scan.checks`.
Exit 0 pass / 1 fail / 77 skip. Never prints a token.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig, l4_inject_entry  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.scan import (  # noqa: E402
    ScanTarget,
    issues,
    require_lane,
    require_verbs,
    start_job,
    wait_terminal,
)

SERVICE = "l4-dns-fault"
GRAMMAR = "dns"
FAULT_CLASSES = {"l4-parser-fault", "l4-crash"}
VERBS = ("scan.start", "scan.status", "scan.issues", "scan.checks")
JOB_TIMEOUT = 300.0


def endpoint(target: ScanTarget) -> dict:
    """`{ip, port, proto, grammar}` for the `l4-dns-fault` `/services` row."""
    row = target.service(SERVICE)
    host, _, port = str(row["addr"]).rpartition(":")
    return {"ip": host, "port": int(port), "proto": row["proto"], "grammar": GRAMMAR}


def run_job(op: BusClient, target: ScanTarget) -> dict:
    started = start_job(
        op, "operator",
        profile_name="l4-stream-safe",
        overrides={"target": {"l4": [endpoint(target)]}},
        confirm=True,
    )
    job = started.get("job")
    check(isinstance(job, str) and job != "", f"scan.start returned a job id (got {job!r})")
    return wait_terminal(op, "operator", job, timeout=JOB_TIMEOUT)


def main() -> int:
    vuln = patched = core = op = None
    try:
        section("1. the seeded DNS-like UDP speaker, in both modes, and an L4-inject core")
        vuln = ScanTarget("vulnerable", l4=True)
        patched = ScanTarget("patched", l4=True)
        v_ep = endpoint(vuln)
        ok(f"vulnerable {SERVICE} on {v_ep['ip']}:{v_ep['port']} ({v_ep['proto']})")
        check(v_ep["proto"] == "udp", f"{SERVICE} is a UDP service (got {v_ep['proto']!r})")
        check(vuln.service(SERVICE).get("grammar") == GRAMMAR,
              f"/services declares grammar {GRAMMAR!r} for {SERVICE}")

        cfg = CoreConfig(
            proxy_port=free_port(),
            browser_proxy_port=free_port(),
            l4_enabled=True,
            l4_scope_entries=[l4_inject_entry()],
        )
        core = Aitm.server(cfg)
        op = BusClient.operator(core)
        require_verbs(op, *VERBS)
        require_lane(op, "l4_stream")
        ok("the core advertises the scan verbs and an l4_stream check")

        section("2. vulnerable: a label length past the datagram end trips the fault")
        vuln.logs.reset()
        status = run_job(op, vuln)
        check(status.get("state") == "done",
              f"the vulnerable job finished `done` (got {status.get('state')!r}, "
              f"stopped_reason={status.get('stopped_reason')!r}, error={status.get('error')!r})")
        total = (status.get("issues") or {}).get("total")
        check(isinstance(total, int) and total >= 1,
              f"the vulnerable job reports issues.total >= 1 (got {total!r})")

        found = issues(op, "operator", job=status.get("job"))
        faults = [i for i in found
                  if i.get("class") in FAULT_CLASSES
                  and ((i.get("location") or {}).get("l4") or {}).get("grammar") == GRAMMAR]
        check(len(faults) >= 1,
              f"at least one issue of class {sorted(FAULT_CLASSES)} names grammar {GRAMMAR!r} "
              f"(got {[(i.get('class'), ((i.get('location') or {}).get('l4') or {}).get('grammar')) for i in found]})")
        ports = {((i.get("location") or {}).get("l4") or {}).get("port") for i in faults}
        check(ports == {v_ep["port"]},
              f"every DNS issue points at the speaker's port {v_ep['port']} (got {sorted(ports)})")

        section("3. the independent observer: the speaker's own L4 log")
        downtime = vuln.logs.downtime(SERVICE)
        check(len(downtime) >= 1,
              f"the vulnerable {SERVICE} logged at least one crash window (got {len(downtime)})")
        inbound = vuln.logs.messages(SERVICE, dir="in")
        check(any(m.get("classified") == "ok" for m in inbound),
              f"some generated datagram parsed as DNS (classified `ok`); "
              f"classes seen: {sorted({m.get('classified') for m in inbound})}")

        section("4. patched: FORMERR, zero issues, no downtime")
        patched.logs.reset()
        p_status = run_job(op, patched)
        check(p_status.get("state") == "done",
              f"the patched job finished `done` (got {p_status.get('state')!r})")
        p_total = (p_status.get("issues") or {}).get("total")
        check(p_total == 0, f"the patched job reports issues.total == 0 (got {p_total!r})")
        p_found = issues(op, "operator", job=p_status.get("job"))
        check(p_found == [],
              f"the patched job filed no issues (got {[i.get('class') for i in p_found]})")
        p_downtime = patched.logs.downtime(SERVICE)
        check(p_downtime == [],
              f"the patched {SERVICE} logged no downtime (got {p_downtime})")
    finally:
        if op:
            op.close()
        if core:
            core.stop()
        for t in (vuln, patched):
            if t:
                t.stop()

    ok("T6-2: the DNS label-length mutation tripped the seeded UDP fault on V, nothing on P")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
