#!/usr/bin/env python3
# e2e: tier=T1 surface=scan needs=http
"""AC T3-3: the five observe-only h2 checks produce exactly the expected set on a
conforming hyper listener, and they stay inside their connection/stream budget.

Arrange: real `aitm-testtarget-serve` V and P, each with its TLS listener (ALPN
`h2, http/1.1`; T10 child spec D1), a real core with `ssl_insecure: true` and both
targets' authorities in scope. The job is an explicit profile: `lanes: ["http"]`,
`checks.include` = the five h2 check ids, `crawl.max_pages: 4` (the scheduler
attaches an origin-scoped check to a discovered point and the target's `/`
carries no parameter of its own, only its links do), `crawl.use_browser:
"never"`, so nothing but the h2 checks and a four-page crawl touches the target.

Assert (T3's pinned expectation on hyper, 2026-11-01; identical on V and P):
exactly one `h2-settings-observe` issue (class `h2-settings`, severity `info`) and
exactly one `h2-rapid-reset-mitigation` issue (class `h2-rapid-reset`, `info`, the
full issue mentions "no reset-rate mitigation"); zero issues for
`h2-pseudo-header-validation`, `h2-header-crlf-tolerance` and
`h2-cl-te-downgrade-indicator` (hyper rejects those frames itself -- true
negatives, and each of the three answers "rejected" through its manual
`check.<id>` verb, which is how the cell shows the variants were written); the
five checks open exactly five raw h2 connections on the `tls` listener beside the
job client's pooled one (told apart by the `host` header the job client's request rows carry and the
raw driver's HEADERS frames do not; `GET /` cannot tell them apart since the
origin-scoped checks run on `<origin>/`), whose per-connection request counters sorted are
`[0, 0, 0, 0, 8]` as hyper really counts them (a rejected header block never
becomes a request; the eight cancelled rapid-reset heads do) and none above 8;
and the issue set on P equals the issue set on V.

Observer, independent of the scanner: the target's control origin `GET /log/conns`
(`alpn`, `opened_ms`, per-connection `requests`, and with T10's #284 the per-connection
`streams` counter: HEADERS frames seen before hyper parses them), which is the T3-3
oracle for "<= 1 connection per check, <= 8 streams": sorted stream counts
`[0, 1, 2, 3, 8]` (amendment 14b plans 0/8/3/2/2; header-crlf's second variant is
never written after the first draws a connection-level GOAWAY) and none above 8. On a build without
`streams` that half is printed as pending, not passed. No fixture.

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
# Per-connection request counters of the five raw-probe connections, sorted, as
# hyper really counts them (T3 PR 2a live run, 2026-11-01): the SETTINGS-only
# probe and the three malformed-header probes have every stream rejected before
# it counts as a request (0), and the rapid-reset probe's eight cancelled
# request heads are counted (8). The job client's own pooled h2 connection (the
# crawl and the checks' baselines) is not a raw-probe connection and is told
# apart by the `GET /` the crawl fetched on it.
EXPECTED_REQUESTS = [0, 0, 0, 0, 8]
# T10's per-connection stream counter (PR #284): distinct client-initiated stream ids
# seen in HEADERS frames on the inbound bytes before hyper parses them, so a rejected
# header block and a cancelled stream count like a served one -- but only the bytes
# hyper's connection task still reads: after a connection-level GOAWAY nothing later
# is counted. The five checks plan 0 (settings), 2 (header-crlf), 2 (cl-te),
# 3 (pseudo-header) and 8 (rapid-reset) streams (spec amendment 14b's 0/8/3/2/2);
# what the target really sees is one fewer for header-crlf, whose first variant
# (CR LF in a header value) draws a connection-level GOAWAY(PROTOCOL_ERROR) from
# hyper, so its second variant is never written (the check says so in its verdict:
# "1 later variant(s) could not be tried"). Live on hyper: [0, 1, 2, 3, 8].
# `streams` is absent on a build without #284, in which case that half is reported
# as pending, not passed.
EXPECTED_STREAMS = [0, 1, 2, 3, 8]
MAX_STREAMS_PER_CONNECTION = 8
JOB_TIMEOUT = 600.0


def h2_profile(name: str, origin: str) -> dict:
    """The observe-only h2 job: a four-page crawl, no browser, only the five h2 checks."""
    return {
        "name": name,
        "target": {"origins": [origin]},
        "lanes": ["http"],
        "intensity": "medium",
        "speed": "normal",
        "accuracy": "normal",
        "checks": {"include": list(H2_CHECKS), "exclude": []},
        # Four pages, not one: the scheduler attaches an origin-scoped check to a
        # discovered point, and the target's `/` carries no parameter of its own
        # (its links do), so a one-page crawl schedules nothing (T3 PR 2a live
        # run, 2026-11-01; the zero-point case is a T1b scheduler follow-up).
        "crawl": {"max_pages": 4, "use_browser": "never"},
        "session": {"mode": "none"},
        "http": {"version": "auto"},
    }


def run_on(op, target, label: str) -> tuple[list, list]:
    """Scan `target`'s TLS origin; return (issues, the h2 connections it opened)."""
    seq0 = target.logs.reset()
    t0 = int(time.time() * 1000)
    job = start_job(op, "operator",
                    profile=h2_profile(f"e2e-t3-h2-observe-{label}", target.tls_base))["job"]
    status = wait_terminal(op, "operator", job, timeout=JOB_TIMEOUT)
    ok(f"{label}: job ended state={status.get('state')!r} "
       f"issues={(status.get('issues') or {}).get('total')!r}")
    # The connections the job client pooled are told from the raw probes by what
    # their requests carry: the job client sends a real request with a `host`
    # header on every row, while the raw driver's HEADERS frames carry no header
    # map at all (the target logs an empty one). `GET /` cannot tell them apart:
    # with amendment 38 the five origin-scoped checks run on `<origin>/`, so the
    # baseline is `GET /` on the pooled connection AND the rapid-reset probe's
    # eight cancelled heads are `GET /` on a raw one (T1b's and T2's live runs).
    def has_host_header(e) -> bool:
        headers = e.get("headers") or {}
        return any(str(k).lower() == "host" for k in headers)
    all_conns = [c for c in target.logs.conns()
                 if c.get("listener") == "tls" and c.get("alpn") == "h2"
                 and int(c.get("opened_ms", 0)) >= t0]
    pooled = {e.get("conn_id") for e in target.logs.scanner_requests(seq0)
              if e.get("listener") == "tls" and has_host_header(e)}
    conns = [c for c in all_conns if c.get("conn_id") not in pooled]
    check(len(pooled) >= 1,
          f"{label}: the job client pooled at least one h2 connection for the crawl (observed {sorted(pooled)})")
    return issues(op, "operator", job=job), conns


def assert_rejections(cfg, target, label: str) -> None:
    """The three silent checks really wrote their malformed variants: by hand, each
    answers Clean with a verdict that names the rejection (hyper resets or GOAWAYs
    the malformed header block), so "no issue" above is a true negative and not a
    probe that sent nothing. Each check observes an origin once per ten minutes
    per check instance, and the job just did, so the manual run uses a core of
    its own (fresh instances) against the same target."""
    # The job's core is still up, so the fresh one takes ports of its own: a new
    # CoreConfig picks every port afresh (a `replace` of the proxy port alone kept
    # the first core's browser proxy port and collided with it).
    fresh_cfg = CoreConfig(proxy_port=free_port(), ssl_insecure=True,
                           scope_entries=list(cfg.scope_entries))
    with Aitm.server(fresh_cfg) as fresh:
        op = BusClient.operator(fresh)
        for check_id in SILENT_CHECKS:
            v = scan_call(op, "operator", f"check.{check_id}",
                          {"url": f"{target.tls_base}/search", "param": "q"}, confirm=True)
            v = json.loads(v) if isinstance(v, str) else v
            detail = str(v.get("detail", ""))
            check(str(v.get("outcome", "")).lower() == "clean" and "rejected" in detail,
                  f"{label}: check.{check_id} by hand is clean with a rejection in its detail "
                  f"(observed {v.get('outcome')!r}: {detail[:120]})")


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
    detail = ", ".join(f"{c.get('conn_id')}:{c.get('requests')}/{c.get('streams')}" for c in conns)
    check(len(conns) == 5,
          f"{label}: the five checks opened exactly five h2 connections "
          f"(observed {len(conns)}: {detail})")
    check(counts == EXPECTED_REQUESTS,
          f"{label}: per-connection request counts (hyper's dispatched requests) are "
          f"{EXPECTED_REQUESTS} (observed {counts}) -- a rejected header block and a "
          f"cancelled stream are never counted here")
    if any(c.get("streams") is None for c in conns):
        print(f"  ~ {label}: the target logs no per-connection stream counter on this build "
              f"(T10 PR #284 not in it); the <= {MAX_STREAMS_PER_CONNECTION} streams/connection "
              f"bound rests on the driver's pre-dial cap (RawH2Plan.streams refused above 8, "
              f"unit-pinned) for this run")
        return
    streams = sorted(int(c["streams"]) for c in conns)
    check(streams == EXPECTED_STREAMS,
          f"{label}: per-connection stream counts (HEADERS frames the target saw, rejected "
          f"and cancelled ones included) are {EXPECTED_STREAMS} (observed {streams})")
    check(all(n <= MAX_STREAMS_PER_CONNECTION for n in streams),
          f"{label}: no connection the checks opened carried more than "
          f"{MAX_STREAMS_PER_CONNECTION} streams (observed {streams})")


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
            assert_rejections(cfg, v, "V")
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
