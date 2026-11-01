#!/usr/bin/env python3
# e2e: tier=T1 surface=scan needs=http
"""AC T3-4: the blind (boolean and timing) checks find the seeded vulns on V, find
nothing on P, stay inside their probe budget, and never sleep in-process.

Arrange: real `aitm-testtarget-serve` V and P, a real core with both authorities in
scope; the `standard` profile narrowed to the three blind checks
(`checks.include: ["sqli-boolean", "sqli-time", "cmdi-time"]`) against the plain
HTTP origin. After the architect's ruling (b) of 2026-11-01 the two SQLi
techniques sit on two different insertion points, so the issue dedupe key of
parent spec D6 keeps them apart: `GET /items?id=` is the boolean seed and never
sleeps, `GET /orders?id=` is the time-based seed.

Assert:
  - `check_id == "sqli-boolean"` on `/items`, class `sqli`, `confidence == "firm"`;
  - `check_id == "sqli-time"` on `/orders`, class `sqli`, with
    `evidence.timing.correlated == True` and `evidence.timing.r >= 0.85`;
  - class `cmdi` on `/ping` with correlated timing evidence;
  - on P none of the three;
  - per point (counted per path over the target's own request log) at most 16
    requests carry a delay payload, 8 per timing check -- the timing checks are
    bounded, not a flood;
  - no bundled active Rhai script calls `sleep(`: the host measures `elapsed_ms`,
    a check never waits itself (parent spec D8.2 "Timing without `sleep`").

Observer, independent of the scanner: the target's control origin `GET /log/http`
-- the `query` strings of the probes it really served (the delay payloads and
their count per path) -- and the script files on disk. Never a fixture.

SKIP 77 when: no `scan.*` verbs, no `http` lane in `scan.checks`, any of
`sqli-boolean` / `sqli-time` / `cmdi-time` missing from the catalogue (T3 is not
merged yet), or no `scripts/bundled/active/*.rhai` on disk. The reason names the
missing thing.
"""

import sys
from pathlib import Path

E2E = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(E2E))

from aitm_e2e import check, free_port, ok, repo_root, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.scan import (  # noqa: E402
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

NEEDED_CHECKS = ("sqli-boolean", "sqli-time", "cmdi-time")
ACTIVE_DIR = Path(repo_root()) / "scripts" / "bundled" / "active"
# The delay dialects the seeds honour (child spec D3): SLEEP(n), pg_sleep(n),
# WAITFOR DELAY '0:0:n', and the shell `sleep n` of the cmdi seed. Matched
# case-insensitively, so `SLEEP`, `pg_sleep` and `sleep` are one token here.
DELAY_TOKENS = ("sleep", "waitfor")
TIMED_PATHS = ("/items", "/orders", "/ping")
# The seeded points, as (path, parameter).
TIMED_POINTS = (("/items", "id"), ("/orders", "id"), ("/ping", "host"))
# Spec D2 caps a timing check at 8 delay probes per point; two timing checks run
# here (`sqli-time`, `cmdi-time`) and both apply to every query point, so one
# point may see up to 16 delay-bearing requests, 8 from each (live run
# 2026-11-01: /items?id saw exactly 16, 8 per check). A point is a (path,
# parameter) pair read from the target's own log: `path` plus the name before
# the first `=` of `query` (form fields are logged without a query, so a POST
# point counts under its path alone).
MAX_DELAY_PROBES_PER_POINT = 16
MIN_TIMING_R = 0.85
JOB_TIMEOUT = 600.0


def by_check(iss, check_id: str, path: str) -> list:
    return [i for i in iss if i.get("check_id") == check_id
            and (i.get("location") or {}).get("path") == path]


def by_class(iss, cls: str, path: str) -> list:
    return [i for i in iss if i.get("class") == cls
            and (i.get("location") or {}).get("path") == path]


def timing_of(op, issue_summary: dict) -> dict:
    """`evidence.timing` of the full Issue behind a summary (fixture scan.issue.json)."""
    full = scan_call(op, "operator", "scan.issue", {"id": issue_summary["id"]})
    return ((full.get("evidence") or {}).get("timing") or {})


def delay_probes_per_point(target, seq0: int) -> dict:
    """{(path, parameter) -> number of requests whose query carried a delay
    payload}, read from the target's own log: the independent count of what the
    timing checks sent to each insertion point."""
    counts: dict = {}
    for e in target.logs.scanner_requests(seq0):
        query = e.get("query") or ""
        if any(tok in query.lower() for tok in DELAY_TOKENS):
            param = query.split("=", 1)[0] if "=" in query else ""
            key = (e.get("path"), param)
            counts[key] = counts.get(key, 0) + 1
    return counts


def run_blind(op, target) -> tuple[list, int, dict]:
    """The three blind checks against `target`'s plain origin; (issues, seq0, the
    number of insertion points the job discovered per (path, parameter), read from
    `scan.sitemap` -- a path can carry the same parameter on more than one node,
    the `/search` link and the search form both carry `q`)."""
    seq0 = target.logs.reset()
    job = start_job(op, "operator", profile_name="standard",
                    overrides={"target": {"origins": [target.base]},
                               "checks": {"include": list(NEEDED_CHECKS)}})["job"]
    status = wait_terminal(op, "operator", job, timeout=JOB_TIMEOUT)
    ok(f"{target.mode}: job ended state={status.get('state')!r} "
       f"probes={(status.get('probes') or {}).get('sent')!r} "
       f"issues={(status.get('issues') or {}).get('total')!r}")
    sitemap = scan_call(op, "operator", "scan.sitemap", {"job": job})
    points_per_key: dict = {}
    for node in (sitemap.get("nodes") or []):
        for param in (node.get("params") or []):
            name = param.get("name") if isinstance(param, dict) else str(param)
            key = (node.get("path_template"), name)
            points_per_key[key] = points_per_key.get(key, 0) + 1
    return issues(op, "operator", job=job), seq0, points_per_key


def main() -> None:
    scripts = sorted(ACTIVE_DIR.glob("*.rhai"))
    if not scripts:
        skip(f"no bundled active scripts at {ACTIVE_DIR} (the no-sleep rule has nothing to check)")

    with boot_target("vulnerable") as v, boot_target("patched") as p:
        cfg = CoreConfig(
            proxy_port=free_port(),
            ssl_insecure=True,
            scope_entries=[v.authority, v.tls_authority, v.tls_h1_authority,
                           p.authority, p.tls_authority, p.tls_h1_authority],
        )
        with Aitm.server(cfg) as core:
            op = BusClient.operator(core)
            require_verbs(op, "scan.start", "scan.status", "scan.issues", "scan.issue", "scan.checks")
            require_lane(op, "http")
            require_checks(op, *NEEDED_CHECKS)

            section("the blind checks find the seeded vulns on V")
            iss_v, seq_v, points_v = run_blind(op, v)

            boolean = by_check(iss_v, "sqli-boolean", "/items")
            check(len(boolean) == 1,
                  f"V: exactly one sqli-boolean issue on /items (observed {len(boolean)}) "
                  f"[{brief(iss_v)}]")
            check(boolean[0].get("class") == "sqli",
                  f"V: the boolean issue has class 'sqli' (observed {boolean[0].get('class')!r})")
            check(boolean[0].get("confidence") == "firm",
                  f"V: the boolean issue is 'firm' (observed {boolean[0].get('confidence')!r})")

            timed = by_check(iss_v, "sqli-time", "/orders")
            check(len(timed) == 1,
                  f"V: exactly one sqli-time issue on /orders (observed {len(timed)}) "
                  f"[{brief(iss_v)}]")
            check(timed[0].get("class") == "sqli",
                  f"V: the time-based issue has class 'sqli' (observed {timed[0].get('class')!r})")
            t_sqli = timing_of(op, timed[0])
            check(t_sqli.get("correlated") is True,
                  f"V: sqli-time evidence.timing.correlated is True (observed {t_sqli.get('correlated')!r})")
            check(isinstance(t_sqli.get("r"), (int, float)) and t_sqli["r"] >= MIN_TIMING_R,
                  f"V: sqli-time evidence.timing.r >= {MIN_TIMING_R} (observed {t_sqli.get('r')!r})")

            cmdi = by_class(iss_v, "cmdi", "/ping")
            check(len(cmdi) >= 1, f"V: a 'cmdi' issue on /ping [{brief(iss_v)}]")
            t_cmdi = timing_of(op, cmdi[0])
            check(t_cmdi.get("correlated") is True,
                  f"V: the cmdi issue carries correlated timing evidence "
                  f"(check_id={cmdi[0].get('check_id')!r}, timing={t_cmdi or None})")

            section("the timing checks are bounded (the target's own request count)")
            counts_v = delay_probes_per_point(v, seq_v)
            shown = {f"{path}?{param}": n for (path, param), n in sorted(counts_v.items())}
            for point in TIMED_POINTS:
                n = counts_v.get(point, 0)
                check(n <= MAX_DELAY_PROBES_PER_POINT,
                      f"V: {n} delay-payload request(s) on {point[0]}?{point[1]} "
                      f"(<= {MAX_DELAY_PROBES_PER_POINT}, 8 per timing check)")
            # A (path, parameter) the job discovered on more than one node is that
            # many points (the engine's own count), each allowed its 16.
            extra = {f"{k[0]}?{k[1]}": (n, points_v.get(k, 1)) for k, n in counts_v.items()
                     if k not in TIMED_POINTS
                     and n > MAX_DELAY_PROBES_PER_POINT * max(1, points_v.get(k, 1))}
            check(not extra,
                  f"V: no other point got more than {MAX_DELAY_PROBES_PER_POINT} delay payloads "
                  f"per discovered point (observed {extra or 'none'}; all points {shown or 'none'}; "
                  f"points per (path, param) {dict((f'{k[0]}?{k[1]}', c) for k, c in points_v.items() if c > 1) or 'all single'})")
            check(sum(counts_v.get(p, 0) for p in TIMED_POINTS[1:]) > 0,
                  f"V: the delay payloads really reached the target (per point {shown or 'none'})")

            section("the patched twin yields none of the three")
            iss_p, seq_p, _points_p = run_blind(op, p)
            leaked = [i for i in iss_p
                      if i.get("check_id") in ("sqli-boolean", "sqli-time")
                      or i.get("class") == "cmdi"]
            check(not leaked, f"P: no boolean / time-based SQLi and no cmdi issue [{brief(iss_p)}]")
            check(len(p.logs.scanner_requests(seq_p)) > 0,
                  "P was probed too: the clean result is the patch, not a missed target")

            section("no bundled active script sleeps in-process")
            sleepers = [f.name for f in scripts
                        if "sleep(" in f.read_text(encoding="utf-8", errors="replace")]
            check(not sleepers,
                  f"none of the {len(scripts)} bundled active script(s) calls sleep( "
                  f"(offenders: {sleepers or 'none'})")

            ok("T3-4: boolean + timing SQLi and cmdi found on V only, bounded probe counts, "
               "no in-script sleep")


if __name__ == "__main__":
    main()
