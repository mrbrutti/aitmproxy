#!/usr/bin/env python3
# e2e: tier=T1 surface=scan needs=http
"""AC T3-1: the HTTP lane's sender really speaks h2 to the target's TLS listener.

Arrange: real `aitm-testtarget-serve` V and P with their TLS listeners (ALPN
`h2, http/1.1`; T10 child spec D1), a real core with `ssl_insecure: true` (the
target's certificate is self-signed) and every target authority in scope;
`scan.start { target: "https://127.0.0.1:<tls port>" }` (the shorthand runs the
default `standard` profile against that origin).

Assert: `probes.by_lane.http > 0`; the seeded reflected XSS on `/search`
(a `REFLECTED_XSS_CLASSES` class, the pinned token) and the seeded SQLi error on
`/products` (class `sqli`) are found
on V and neither is found on P; `flow.detail` of `evidence.probe_flows[0]` of one
of those issues renders `response.version` as `h2` or `HTTP/2` (the version the
sender negotiated, plan session call S1; the recorded request keeps the version
it was built with, so `request.version` is only the fallback when a build has no
response version; the cell prints which; plan call P7).

Observer, independent of the scanner: the target's own control origin,
`GET /log/http` -- `request` entries with `version: "h2"` and
`listener: "tls"`, and zero V-class issues on the patched twin. No fixture.

SKIP 77 when: the build advertises no `scan.*` verbs, `scan.checks` lists no
`http`-lane check, or the T3 check ids `xss-reflected` / `sqli` are missing
(T3 is not merged yet). The reason always names the missing thing.
"""

import sys
from pathlib import Path

E2E = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(E2E))

from aitm_e2e import check, free_port, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.scan import (  # noqa: E402
    REFLECTED_XSS_CLASSES,
    boot_target,
    brief,
    issues,
    require_checks,
    require_lane,
    require_verbs,
    scan_call,
    start_job,
    wait_terminal,
)

# The T3 check ids this cell needs in the live catalogue (parent spec D8.2). These are
# CHECK ids, a vocabulary of their own; the issue class is `REFLECTED_XSS_CLASSES`.
NEEDED_CHECKS = ("xss-reflected", "sqli")
XSS_LABEL = "/".join(REFLECTED_XSS_CLASSES)
JOB_TIMEOUT = 600.0


def find(iss, cls, path: str) -> list:
    """Issues at `path` whose class is `cls` (one token) or is in `cls` (a tuple)."""
    classes = (cls,) if isinstance(cls, str) else tuple(cls)
    return [i for i in iss
            if i.get("class") in classes and (i.get("location") or {}).get("path") == path]


def run_job(op, target, origin: str) -> tuple[str, dict]:
    """Reset the target's logs, scan `origin`, wait for a terminal state."""
    seq0 = target.logs.reset()
    started = start_job(op, "operator", target=origin)
    job = started["job"]
    status = wait_terminal(op, "operator", job, timeout=JOB_TIMEOUT)
    return job, {"seq0": seq0, "status": status}


def main() -> None:
    with boot_target("vulnerable") as v, boot_target("patched") as p:
        if not v.tls_base or not p.tls_base:
            skip("the test target did not start a TLS listener (needs --tls-port; T10 D1)")
        cfg = CoreConfig(
            proxy_port=free_port(),
            ssl_insecure=True,
            scope_entries=[v.tls_authority, v.tls_h1_authority, v.authority,
                           p.tls_authority, p.tls_h1_authority, p.authority],
        )
        with Aitm.server(cfg) as core:
            op = BusClient.operator(core)
            require_verbs(op, "scan.start", "scan.status", "scan.issues", "scan.issue",
                          "scan.checks", "flow.detail")
            require_lane(op, "http")
            require_checks(op, *NEEDED_CHECKS)

            section("the job runs over the target's h2 TLS listener (V)")
            job_v, ctx = run_job(op, v, v.tls_base)
            status = ctx["status"]
            by_lane = ((status.get("probes") or {}).get("by_lane") or {})
            check(by_lane.get("http", 0) > 0,
                  f"probes.by_lane.http > 0 (state={status.get('state')!r}, by_lane={by_lane})")

            reqs = v.logs.scanner_requests(ctx["seq0"])
            h2_tls = [e for e in reqs if e.get("version") == "h2" and e.get("listener") == "tls"]
            check(h2_tls, f"the target logged {len(h2_tls)} h2 request(s) on listener 'tls' "
                          f"(of {len(reqs)} scanner requests)")

            section("the seeded vulns are found over h2 on V")
            iss_v = issues(op, "operator", job=job_v)
            xss = find(iss_v, REFLECTED_XSS_CLASSES, "/search")
            sqli = find(iss_v, "sqli", "/products")
            check(len(xss) >= 1,
                  f"V: class '{XSS_LABEL}' on /search found over h2 [{brief(iss_v)}]")
            check(len(sqli) >= 1, f"V: class 'sqli' on /products found over h2 [{brief(iss_v)}]")

            section("one issue's probe flow was captured as an h2 flow")
            flows = []
            chosen = None
            for cand in (xss + sqli):
                full = scan_call(op, "operator", "scan.issue", {"id": cand["id"]})
                flows = ((full.get("evidence") or {}).get("probe_flows") or [])
                if flows:
                    chosen = full
                    break
            check(chosen is not None and flows,
                  "an issue carries evidence.probe_flows (the probes were recorded)")
            detail = op.call("flow.detail", {"id": flows[0], "body": "none"})
            version = ((detail.get("response") or {}).get("version")
                       or (detail.get("request") or {}).get("version") or "")
            check(version in ("h2", "HTTP/2"),
                  f"probe flow {flows[0]} response.version is h2 (rendered {version!r})")
            ok(f"this build renders the h2 version as {version!r} (plan call P7 accepts either)")

            section("the patched twin yields neither class over h2")
            job_p, ctx_p = run_job(op, p, p.tls_base)
            iss_p = issues(op, "operator", job=job_p)
            check(not find(iss_p, REFLECTED_XSS_CLASSES, "/search"),
                  f"P: no '{XSS_LABEL}' issue on /search [{brief(iss_p)}]")
            check(not find(iss_p, "sqli", "/products"),
                  f"P: no 'sqli' issue on /products [{brief(iss_p)}]")
            p_h2 = [e for e in p.logs.scanner_requests(ctx_p["seq0"])
                    if e.get("version") == "h2" and e.get("listener") == "tls"]
            check(p_h2, f"P was probed over h2 too ({len(p_h2)} h2 requests on 'tls'): "
                        "the absence of issues is the patch, not a missed target")

            ok("T3-1: the sender negotiated h2, the seeded vulns were found over it on V only")


if __name__ == "__main__":
    main()
