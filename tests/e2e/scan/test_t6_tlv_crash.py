#!/usr/bin/env python3
# e2e: tier=T1 surface=scan needs=l4
"""scan/t6_tlv_crash -- AC T6-1: the generic TLV grammar infers the 2-byte
big-endian length relation from the seed set, desyncs it, and the seeded
length-prefixed TCP service crashes for its bounded window.

What is proven, on a REAL core with the L4 stream lane and the REAL seeded
speaker `l4-tlv-crash` (`aitm-testtarget-serve --l4`, child spec D5: frame =
u16 BE len + payload; V triggers on a declared length > 4096 or a declared
length larger than the bytes that arrived after a 200 ms idle; P answers
`00 03 45 52 52` and closes):

  * a job started with the built-in `l4-stream-safe` profile (child spec D5,
    parent D8.5) plus `overrides.target.l4` and three well-formed seeds
    (`000161`, `00026162`, `0003616263`, so the TLV inference has a set to fit
    a descriptor against) reaches a terminal `done`;
  * exactly one issue of class `l4-crash` whose `location.l4.grammar` is
    `tlv` and whose `evidence.l4.mutation_chain` names `len_desync`, with
    `evidence.l4.reproduced == [3, 3]` (the find replayed three times out of
    three, parent D8.5 "reproduced `reproduce_count` times");
  * the INDEPENDENT observer: the target's own `/log/l4` `downtime` ring for
    `l4-tlv-crash` holds at least one crash window (the speaker, not the
    scanner, says it went down);
  * the same job against the PATCHED target yields zero issues and an empty
    `downtime` ring.

Observer: the seeded speaker's own control-origin log (`TargetLogs.downtime`),
never the scanner's own account of itself.

SKIPs 77 (never a FAIL):
  * the core does not advertise the `scan.*` verbs this cell calls;
  * `scan.checks` lists no check for the `l4_stream` lane (the T6 lane has not
    landed on this build);
  * `aitm-testtarget-serve` is not built (`boot_target` SKIPs 77 naming the build
    command, the same way in every cell).

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
    boot_target,
    issue,
    issues,
    l4_endpoint,
    require_lane,
    require_verbs,
    run_to_terminal,
)

SERVICE = "l4-tlv-crash"
GRAMMAR = "tlv"
# Three well-formed TLV frames (u16 BE length + payload): "a", "ab", "abc".
SEEDS = [{"hex": "000161"}, {"hex": "00026162"}, {"hex": "0003616263"}]
VERBS = ("scan.start", "scan.status", "scan.issues", "scan.issue", "scan.checks")
# A bounded L4 stream job against one local speaker; 300 s is generous for it.
JOB_TIMEOUT = 300.0


def run_job(op: BusClient, target: ScanTarget) -> dict:
    """Start the TLV stream job against `target` and return its terminal JobStatus."""
    job, final = run_to_terminal(
        op, "operator", timeout=JOB_TIMEOUT,
        profile_name="l4-stream-safe",
        overrides={"target": {"l4": [l4_endpoint(target, SERVICE, GRAMMAR)]}, "l4": {"seeds": SEEDS}},
        confirm=True,
    )
    ok(f"scan.start returned a job id ({job})")
    return final


def main() -> int:
    vuln = patched = core = op = None
    try:
        section("1. the seeded TLV speaker, in both modes, and a core with the L4 inject scope")
        vuln = boot_target("vulnerable", l4=True)
        patched = boot_target("patched", l4=True)
        v_ep = l4_endpoint(vuln, SERVICE, GRAMMAR)
        p_ep = l4_endpoint(patched, SERVICE, GRAMMAR)
        ok(f"vulnerable {SERVICE} on {v_ep['ip']}:{v_ep['port']} ({v_ep['proto']}), "
           f"patched on {p_ep['ip']}:{p_ep['port']}")
        check(v_ep["proto"] == "tcp", f"{SERVICE} is a TCP service (got {v_ep['proto']!r})")
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

        section("2. vulnerable: the TLV length relation is desynced and the speaker crashes")
        vuln.logs.reset()
        status = run_job(op, vuln)
        check(status.get("state") == "done",
              f"the vulnerable job finished `done` (got {status.get('state')!r}, "
              f"stopped_reason={status.get('stopped_reason')!r}, error={status.get('error')!r})")
        job = status.get("job")

        found = issues(op, "operator", job=job)
        crashes = [i for i in found if i.get("class") == "l4-crash"]
        check(len(crashes) == 1,
              f"exactly one `l4-crash` issue (got {len(crashes)} of {len(found)} issues: "
              f"{[i.get('class') for i in found]})")
        summary = crashes[0]
        loc_l4 = (summary.get("location") or {}).get("l4") or {}
        check(loc_l4.get("grammar") == GRAMMAR,
              f"the issue's location.l4.grammar is {GRAMMAR!r} (got {loc_l4.get('grammar')!r})")
        check(loc_l4.get("port") == v_ep["port"],
              f"the issue points at the speaker's port {v_ep['port']} (got {loc_l4.get('port')!r})")

        full = issue(op, "operator", summary["id"])
        ev_l4 = (full.get("evidence") or {}).get("l4") or {}
        chain = ev_l4.get("mutation_chain")
        # Chain entries are `mutator(path,params)` (T6 S6.3; the shared contract
        # note), e.g. `len_desync(length,+1)`: match the mutator name, not the
        # whole entry.
        check(isinstance(chain, list)
              and any(isinstance(m, str) and m.split("(", 1)[0] == "len_desync" for m in chain),
              f"evidence.l4.mutation_chain names `len_desync` (got {chain!r})")
        check(ev_l4.get("reproduced") == [3, 3],
              f"evidence.l4.reproduced is [3, 3] (got {ev_l4.get('reproduced')!r})")

        section("3. the independent observer: the speaker's own downtime ring")
        downtime = vuln.logs.downtime(SERVICE)
        check(len(downtime) >= 1,
              f"the vulnerable {SERVICE} logged at least one crash window "
              f"(got {len(downtime)})")
        first = downtime[0]
        check(int(first.get("up_at_ms", 0)) - int(first.get("down_at_ms", 0)) == 5000,
              f"the crash window is the spec's 5 000 ms (got "
              f"{int(first.get('up_at_ms', 0)) - int(first.get('down_at_ms', 0))} ms)")

        section("4. patched: the same job finds nothing and the speaker never goes down")
        patched.logs.reset()
        p_status = run_job(op, patched)
        check(p_status.get("state") == "done",
              f"the patched job finished `done` (got {p_status.get('state')!r})")
        p_total = ((p_status.get("issues") or {}).get("total"))
        check(p_total == 0, f"the patched job reports issues.total == 0 (got {p_total!r})")
        p_found = issues(op, "operator", job=p_status.get("job"))
        check(p_found == [], f"the patched job filed no issues (got {[i.get('class') for i in p_found]})")
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

    ok("T6-1: TLV len_desync crashed the seeded speaker, reproduced [3, 3], clean on patched")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
