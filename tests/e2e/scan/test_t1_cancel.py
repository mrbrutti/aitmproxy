#!/usr/bin/env python3
# e2e: tier=T1 surface=scan needs=http
"""T1-2: `scan.cancel` on a running job reaches `cancelled` within 5 s and the
probes actually STOP; and the job never leaves its scope.

Observers (never the scanner's own account of itself):
  - the target's own control log: no scanner request is recorded more than 2 s
    after the job's `finished_at`, and `probes.sent` never exceeds the number of
    requests the target really received;
  - an out-of-scope `Canary()` loopback listener. A link to it is planted in the
    target's stored-XSS comment store (`POST /comments`, direct, NOT through the
    proxy, so the plant is the target's own content and not a scan artefact), so
    the crawler is offered a way out of scope on a page it will fetch. The canary
    must record ZERO hits for the job's whole life. This is how confinement is
    proven without an `egress.probe` verb (AC T1-2: none is shipped).

SKIPs 77 when the live core lacks `scan.start` / `scan.status` / `scan.cancel`.
"""
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

E2E = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(E2E))

from aitm_e2e import check, fail, free_port, ok, section  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.scan import (  # noqa: E402
    Canary,
    ScanTarget,
    cancel,
    require_verbs,
    scan_call,
    start_job,
    wait_terminal,
)

# Literals of AC T1-2 / plan task B5.
MIN_PROBES_BEFORE_CANCEL = 5
PROBE_WAIT_S = 60.0
CANCEL_TERMINAL_S = 5.0
QUIET_AFTER_FINISH_MS = 2000
SETTLE_S = 2.5


def plant_canary_link(target_base: str, canary: Canary) -> int:
    """`POST /comments` on the target with a link to the out-of-scope canary, sent
    DIRECTLY (not via the proxy) so the link is the target's own stored content.
    Returns the HTTP status the target answered."""
    body = urllib.parse.urlencode({"comment": canary.link_html("/leak")}).encode("utf-8")
    req = urllib.request.Request(
        target_base + "/comments", data=body, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:  # noqa: S310  (loopback only)
            return resp.status
    except urllib.error.HTTPError as e:  # a 3xx/4xx is still an answer we can report
        return e.code


def main() -> None:
    with ScanTarget("vulnerable") as v, Canary() as canary:
        findings_dir = tempfile.mkdtemp(prefix="aitm-e2e-scan-t1-cancel-")
        # The canary's authority is deliberately absent from scope_entries.
        cfg = CoreConfig(
            proxy_port=free_port(),
            scope_entries=[v.authority],
            findings_dir=findings_dir,
        )
        with Aitm.server(cfg) as core:
            op = BusClient.operator(core)
            require_verbs(op, "scan.start", "scan.status", "scan.cancel")

            section("plant an out-of-scope link in the target's comment store")
            status = plant_canary_link(v.base, canary)
            check(status in {200, 302, 303},
                  f"POST /comments accepted the planted canary link (status {status})")
            check(canary.hits == [],
                  f"planting did not itself hit the canary (hits={canary.hits})")

            # Reset AFTER planting: every request the log holds from here is the job's.
            seq0 = v.logs.reset()

            section("start a scan and let it get going")
            job = start_job(op, "operator", target=v.base)["job"]
            deadline = time.monotonic() + PROBE_WAIT_S
            st = {}
            while True:
                st = scan_call(op, "operator", "scan.status", {"job": job})
                sent = ((st.get("probes") or {}).get("sent") or 0)
                if sent >= MIN_PROBES_BEFORE_CANCEL:
                    break
                if st.get("state") in {"done", "cancelled", "failed"}:
                    fail(f"job went terminal ({st.get('state')!r}, "
                         f"stopped_reason={st.get('stopped_reason')!r}) after only {sent} "
                         f"probe(s); cannot exercise cancel on a running job")
                    return
                if time.monotonic() >= deadline:
                    fail(f"job sent only {sent} probe(s) in {PROBE_WAIT_S}s "
                         f"(need >= {MIN_PROBES_BEFORE_CANCEL}; state={st.get('state')!r})")
                    return
                time.sleep(0.2)
            ok(f"job {job} reached probes.sent={((st.get('probes') or {}).get('sent'))}")

            section("scan.cancel reaches cancelled within 5 s")
            t_c = time.monotonic()
            c = cancel(op, "operator", job)
            check(c.get("state") in {"cancelling", "cancelled"},
                  f"scan.cancel answered state cancelling|cancelled, got {c.get('state')!r}")
            try:
                final = wait_terminal(op, "operator", job, timeout=CANCEL_TERMINAL_S, poll=0.2)
            except TimeoutError as e:
                fail(f"not terminal within {CANCEL_TERMINAL_S}s of scan.cancel: {e}")
                return
            cancel_s = time.monotonic() - t_c
            check(cancel_s <= CANCEL_TERMINAL_S,
                  f"job went terminal {cancel_s:.3f}s after scan.cancel (<= {CANCEL_TERMINAL_S}s)")
            check(final.get("state") == "cancelled",
                  f"terminal state is cancelled, got {final.get('state')!r}")
            finished_at = final.get("finished_at")
            check(isinstance(finished_at, int) and finished_at > 0,
                  f"finished_at is set on the cancelled job: {finished_at!r}")
            if not isinstance(finished_at, int):
                return

            section("the probes really stopped (the target's own log says so)")
            time.sleep(SETTLE_S)
            reqs = v.logs.scanner_requests(seq0)
            late = [e for e in reqs if int(e.get("ts_ms", 0)) > finished_at + QUIET_AFTER_FINISH_MS]
            check(len(late) == 0,
                  f"no scanner request reached the target more than "
                  f"{QUIET_AFTER_FINISH_MS} ms after finished_at "
                  f"(late={len(late)}: {[e.get('path') for e in late[:5]]})")

            section("the job never left its scope")
            check(canary.hits == [],
                  f"the out-of-scope canary recorded zero hits for the job's whole life "
                  f"(hits={[h['path'] for h in canary.hits]})")

            sent = ((final.get("probes") or {}).get("sent") or 0)
            check(sent <= len(reqs),
                  f"probes.sent ({sent}) <= requests the target really received "
                  f"({len(reqs)})")
            op.close()


if __name__ == "__main__":
    main()
