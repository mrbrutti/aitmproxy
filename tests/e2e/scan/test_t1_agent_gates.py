#!/usr/bin/env python3
# e2e: tier=T1 surface=scan needs=http serial
"""T1-4: the agent gate on `scan.start`.

Core A (no `scanner:` section, default agent policy):
  - an agent `BusClient` is REFUSED `scan.start` with the D3 code `refused_agent`;
  - the same agent IS allowed `scan.map` (mapping is not an active scan).
Core B (`scanner.allow_agent_active: true`, operator sets the agent policy to
`all`): the same agent's `scan.start` succeeds and the job reaches `done`.

The flag reaches the core only through the harness's `CoreConfig(scanner=
ScannerSection(...))` emitter (AC T1-4: never a hand-written config).

Observer: the target's OWN control log. After the refusal it must hold zero
scanner requests — a refusal that still touched the origin would be a leak; after
the allowed run it must be non-empty.

`serial`: this cell changes the agent policy on its own core and boots two cores
in sequence against one target.

`scanner:` is an unknown top-level key to a pre-T1b core (`deny_unknown_fields`
in `crates/aitm/src/config_file.rs`), so such a core FAILS TO BOOT rather than
ignoring it. Core A therefore doubles as the probe core: `require_verbs` runs on
it, and core B (which carries the section) is booted only after that passed.
"""
import sys
import tempfile
from pathlib import Path

E2E = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(E2E))

from aitm_e2e import check, fail, free_port, ok, section  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig, ScannerSection  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.scan import (  # noqa: E402
    ScanTarget,
    cancel,
    require_verbs,
    scan_error_code,
    scan_try,
    wait_terminal,
)

TERMINAL_TIMEOUT_S = 600.0


def main() -> None:
    with ScanTarget("vulnerable") as v:
        # --- core A: no `scanner:` section; also the probe core for require_verbs ---
        cfg_a = CoreConfig(
            proxy_port=free_port(),
            scope_entries=[v.authority],
            findings_dir=tempfile.mkdtemp(prefix="aitm-e2e-scan-t1-gates-a-"),
        )
        with Aitm.server(cfg_a) as core_a:
            op = BusClient.operator(core_a)
            require_verbs(op, "scan.start", "scan.map", "scan.status", "scan.cancel")
            ag = BusClient.agent(core_a)

            section("core A: the agent is refused scan.start with refused_agent")
            seq_a = v.logs.reset()
            status, payload = scan_try(ag, "agent", "scan.start", {"target": v.base})
            check(status == "error",
                  f"scan.start at the agent role was refused (got {status!r}: {payload!r})")
            code = scan_error_code(str(payload))
            check(code == "refused_agent",
                  f"the refusal carries the D3 code refused_agent, got {code!r} "
                  f"from {payload!r}")

            refused_reqs = v.logs.scanner_requests(seq_a)
            check(refused_reqs == [],
                  f"the refused scan.start touched the target zero times "
                  f"(log holds {len(refused_reqs)} request(s))")

            section("core A: the same agent IS allowed scan.map")
            status, payload = scan_try(ag, "agent", "scan.map", {"target": v.base})
            check(status == "ok",
                  f"scan.map at the agent role succeeded without the active flag "
                  f"(got {status!r}: {payload!r})")
            if status != "ok":
                return
            map_job_id = payload.get("job") if isinstance(payload, dict) else None
            check(isinstance(map_job_id, str) and map_job_id.startswith("scan-"),
                  f"scan.map returned a scan- job id: {map_job_id!r}")
            if isinstance(map_job_id, str):
                cancel(op, "operator", map_job_id)
                try:
                    wait_terminal(op, "operator", map_job_id, timeout=30.0, poll=0.2)
                    ok(f"map job {map_job_id} cancelled and terminal")
                except TimeoutError as e:
                    fail(f"the cancelled map job never went terminal: {e}")
                    return
            ag.close()
            op.close()

        # --- core B: scanner.allow_agent_active: true, agent policy `all` ---
        cfg_b = CoreConfig(
            proxy_port=free_port(),
            scope_entries=[v.authority],
            findings_dir=tempfile.mkdtemp(prefix="aitm-e2e-scan-t1-gates-b-"),
            scanner=ScannerSection(allow_agent_active=True),
        )
        with Aitm.server(cfg_b) as core_b:
            op2 = BusClient.operator(core_b)
            section("core B: scanner.allow_agent_active + agent policy all")
            policy = op2.call("agent.set", {"policy": "all"})
            check(isinstance(policy, dict) and policy.get("policy") == "all",
                  f"the operator set the agent policy to all (got {policy!r})")

            ag2 = BusClient.agent(core_b)
            seq_b = v.logs.reset()
            status, payload = scan_try(ag2, "agent", "scan.start", {"target": v.base})
            check(status == "ok",
                  f"scan.start at the agent role succeeded with the flag "
                  f"(got {status!r}: {payload!r})")
            if status != "ok":
                return
            job = payload.get("job") if isinstance(payload, dict) else None
            check(isinstance(job, str) and job.startswith("scan-"),
                  f"scan.start returned a scan- job id: {job!r}")
            if not isinstance(job, str):
                return

            try:
                final = wait_terminal(op2, "operator", job, timeout=TERMINAL_TIMEOUT_S)
            except TimeoutError as e:
                fail(str(e))
                return
            check(final.get("state") == "done",
                  f"the agent-started job reached done (got {final.get('state')!r}, "
                  f"stopped_reason={final.get('stopped_reason')!r})")

            allowed_reqs = v.logs.scanner_requests(seq_b)
            check(len(allowed_reqs) > 0,
                  f"the allowed agent scan really hit the target "
                  f"({len(allowed_reqs)} request(s) in its own log)")
            ag2.close()
            op2.close()


if __name__ == "__main__":
    main()
