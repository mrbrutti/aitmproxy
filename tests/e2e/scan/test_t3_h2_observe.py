#!/usr/bin/env python3
# e2e: tier=T1 surface=scan needs=http
"""AC T3-3: the five observe-only h2 checks produce exactly the expected set on a
conforming hyper listener, and they stay inside their connection/stream budget.

Arrange: real `aitm-testtarget-serve` V and P, each with its TLS listener (ALPN
`h2, http/1.1`; T10 child spec D1), a real core with `ssl_insecure: true` and both
targets' authorities in scope. The job is an explicit profile: `lanes: ["http"]`,
`checks.include` = the five h2 check ids, `crawl.max_pages: 1`,
`crawl.use_browser: "never"`, so nothing but the h2 checks and a one-page crawl
touches the target.

Assert (T3's pinned expectation on hyper, 2026-11-01; identical on V and P):
exactly one `h2-settings-observe` issue (class `h2-settings`, severity `info`) and
exactly one `h2-rapid-reset-mitigation` issue (class `h2-rapid-reset`, `info`, the
full issue mentions "no reset-rate mitigation"); zero issues for
`h2-pseudo-header-validation`, `h2-header-crlf-tolerance` and
`h2-cl-te-downgrade-indicator` (hyper rejects those frames itself -- true
negatives); the five checks open exactly five h2 connections on the `tls`
listener, whose per-connection request counters sorted are `[0, 2, 2, 3, 8]` and
none above 8; and the issue set on P equals the issue set on V.

Observer, independent of the scanner: the target's control origin `GET /log/conns`
(`alpn`, `opened_ms`, per-connection `requests`), which is the T3-3 oracle for
"<= 1 connection per check, <= 8 streams". No fixture.

SKIP 77 when: no `scan.*` verbs, no `http` lane in `scan.checks`, any of the five
h2 check ids is missing from the catalogue (T3 is not merged yet), or the target
started no TLS listener. The reason names the missing thing.
"""

import json
import sys
import time
from pathlib import Path

E2E = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(E2E))

from aitm_e2e import check, free_port, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.scan import (  # noqa: E402
    boot_target,
    issues,
    require_checks,
    require_lane,
    require_verbs,
    scan_call,
    start_job,
    wait_terminal,
)

H2_CHECKS = ["h2-settings-observe", "h2-header-crlf-tolerance", "h2-pseudo-header-validation",
             "h2-rapid-reset-mitigation", "h2-cl-te-downgrade-indicator"]
# (check_id, class) of the two issues hyper really provokes; both `info`.
EXPECTED_ISSUES = (("h2-settings-observe", "h2-settings"),
                   ("h2-rapid-reset-mitigation", "h2-rapid-reset"))
SILENT_CHECKS = ("h2-pseudo-header-validation", "h2-header-crlf-tolerance",
                 "h2-cl-te-downgrade-indicator")
RAPID_RESET_PHRASE = "no reset-rate mitigation"
EXPECTED_REQUESTS = [0, 2, 2, 3, 8]
JOB_TIMEOUT = 600.0


def h2_profile(name: str, origin: str) -> dict:
    """The observe-only h2 job: one page, no browser, only the five h2 checks."""
    return {
        "name": name,
        "target": {"origins": [origin]},
        "lanes": ["http"],
        "intensity": "medium",
        "speed": "normal",
        "accuracy": "normal",
        "checks": {"include": list(H2_CHECKS), "exclude": []},
        "crawl": {"max_pages": 1, "use_browser": "never"},
        "session": {"mode": "none"},
        "http": {"version": "auto"},
    }


def run_on(op, target, label: str) -> tuple[list, list]:
    """Scan `target`'s TLS origin; return (issues, the h2 connections it opened)."""
    target.logs.reset()
    t0 = int(time.time() * 1000)
    job = start_job(op, "operator",
                    profile=h2_profile(f"e2e-t3-h2-observe-{label}", target.tls_base))["job"]
    status = wait_terminal(op, "operator", job, timeout=JOB_TIMEOUT)
    ok(f"{label}: job ended state={status.get('state')!r} "
       f"issues={(status.get('issues') or {}).get('total')!r}")
    conns = [c for c in target.logs.conns()
             if c.get("listener") == "tls" and c.get("alpn") == "h2"
             and int(c.get("opened_ms", 0)) >= t0]
    return issues(op, "operator", job=job), conns


def assert_issue_set(op, iss, label: str) -> set:
    by_id: dict = {}
    for i in iss:
        by_id.setdefault(i.get("check_id"), []).append(i)
    observed = sorted(f"{k}x{len(v)}" for k, v in by_id.items())
    for check_id, cls in EXPECTED_ISSUES:
        got = by_id.get(check_id, [])
        check(len(got) == 1,
              f"{label}: exactly one {check_id} issue (observed {observed})")
        check(got[0].get("class") == cls,
              f"{label}: {check_id} has class {cls!r} (observed {got[0].get('class')!r})")
        check(got[0].get("severity") == "info",
              f"{label}: {check_id} severity is 'info' (observed {got[0].get('severity')!r})")
    for check_id in SILENT_CHECKS:
        check(check_id not in by_id,
              f"{label}: no {check_id} issue -- hyper is conforming (observed {observed})")
    rr = by_id["h2-rapid-reset-mitigation"][0]
    full = scan_call(op, "operator", "scan.issue", {"id": rr["id"]})
    text = json.dumps(full)
    check(RAPID_RESET_PHRASE in text,
          f"{label}: the rapid-reset issue says {RAPID_RESET_PHRASE!r}")
    return set(by_id)


def assert_connections(conns, label: str) -> None:
    counts = sorted(int(c.get("requests", 0)) for c in conns)
    detail = ", ".join(f"{c.get('conn_id')}:{c.get('requests')}" for c in conns)
    check(len(conns) == 5,
          f"{label}: the five checks opened exactly five h2 connections "
          f"(observed {len(conns)}: {detail})")
    check(counts == EXPECTED_REQUESTS,
          f"{label}: per-connection request counts are {EXPECTED_REQUESTS} "
          f"(observed {counts}) -- the exact list, so the <= 8 streams/connection "
          f"bound holds by construction")


def main() -> None:
    with boot_target("vulnerable") as v, boot_target("patched") as p:
        if not v.tls_base or not p.tls_base:
            skip("the test target started no TLS listener (needs --tls-port; T10 child spec D1)")
        cfg = CoreConfig(
            proxy_port=free_port(),
            ssl_insecure=True,
            scope_entries=[v.tls_authority, v.tls_h1_authority, v.authority,
                           p.tls_authority, p.tls_h1_authority, p.authority],
        )
        with Aitm.server(cfg) as core:
            op = BusClient.operator(core)
            require_verbs(op, "scan.start", "scan.status", "scan.issues", "scan.issue", "scan.checks")
            require_lane(op, "http")
            require_checks(op, *H2_CHECKS)

            section("the observe-only h2 checks on V")
            iss_v, conns_v = run_on(op, v, "V")
            ids_v = assert_issue_set(op, iss_v, "V")
            assert_connections(conns_v, "V")

            section("the same run on the patched twin")
            iss_p, conns_p = run_on(op, p, "P")
            ids_p = assert_issue_set(op, iss_p, "P")
            assert_connections(conns_p, "P")

            check(ids_v == ids_p,
                  f"V and P produce the identical h2 issue set ({sorted(ids_v)} vs {sorted(ids_p)})")

            ok("T3-3: two info issues, three true negatives, five bounded h2 connections, "
               "identical on V and P")


if __name__ == "__main__":
    main()
