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
  - per point (counted per path over the target's own request log) at most 8
    requests carry a delay payload -- the timing checks are bounded, not a flood;
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
from aitm_e2e.scan import (ScanTarget, issues, require_lane, require_verbs,  # noqa: E402
                           scan_call, start_job, wait_terminal)

NEEDED_CHECKS = ("sqli-boolean", "sqli-time", "cmdi-time")
ACTIVE_DIR = Path(repo_root()) / "scripts" / "bundled" / "active"
# The delay dialects the seeds honour (child spec D3): SLEEP(n), pg_sleep(n),
# WAITFOR DELAY '0:0:n', and the shell `sleep n` of the cmdi seed. Matched
# case-insensitively, so `SLEEP`, `pg_sleep` and `sleep` are one token here.
DELAY_TOKENS = ("sleep", "waitfor")
TIMED_PATHS = ("/items", "/orders", "/ping")
MAX_DELAY_PROBES_PER_POINT = 8
MIN_TIMING_R = 0.85
JOB_TIMEOUT = 600.0


def require_checks(op, ids) -> None:
    """SKIP 77 naming every check id the live `scan.checks` catalogue lacks."""
    live = {c.get("id") for c in (scan_call(op, "operator", "scan.checks", {}) or {}).get("checks", [])
            if isinstance(c, dict)}
    missing = [i for i in ids if i not in live]
    if missing:
        skip("missing check id " + ", ".join(missing) + " in scan.checks (T3 is not on this build)")


def brief(iss, limit: int = 12) -> str:
    rows = sorted({(i.get("class"), i.get("check_id"), (i.get("location") or {}).get("path"))
                   for i in iss if isinstance(i, dict)})
    shown = ", ".join(f"{c}/{cid}@{p}" for c, cid, p in rows[:limit])
    return f"{len(rows)} kind(s): {shown}{' ...' if len(rows) > limit else ''}"


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


def delay_probes_per_path(target, seq0: int) -> dict:
    """{path -> number of requests whose query carried a delay payload}, read from
    the target's own log: the independent count of what the timing checks sent."""
    counts: dict = {}
    for e in target.logs.scanner_requests(seq0):
        query = (e.get("query") or "").lower()
        if any(tok in query for tok in DELAY_TOKENS):
            counts[e.get("path")] = counts.get(e.get("path"), 0) + 1
    return counts


def run_blind(op, target) -> tuple[list, int]:
    """The three blind checks against `target`'s plain origin; (issues, seq0)."""
    seq0 = target.logs.reset()
    job = start_job(op, "operator", profile_name="standard",
                    overrides={"target": {"origins": [target.base]},
                               "checks": {"include": list(NEEDED_CHECKS)}})["job"]
    status = wait_terminal(op, "operator", job, timeout=JOB_TIMEOUT)
    ok(f"{target.mode}: job ended state={status.get('state')!r} "
       f"probes={(status.get('probes') or {}).get('sent')!r} "
       f"issues={(status.get('issues') or {}).get('total')!r}")
    return issues(op, "operator", job=job), seq0


def main() -> None:
    scripts = sorted(ACTIVE_DIR.glob("*.rhai"))
    if not scripts:
        skip(f"no bundled active scripts at {ACTIVE_DIR} (the no-sleep rule has nothing to check)")

    with ScanTarget("vulnerable") as v, ScanTarget("patched") as p:
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
            require_checks(op, NEEDED_CHECKS)

            section("the blind checks find the seeded vulns on V")
            iss_v, seq_v = run_blind(op, v)

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
            counts_v = delay_probes_per_path(v, seq_v)
            for path in TIMED_PATHS:
                n = counts_v.get(path, 0)
                check(n <= MAX_DELAY_PROBES_PER_POINT,
                      f"V: {n} delay-payload request(s) on {path} (<= {MAX_DELAY_PROBES_PER_POINT})")
            extra = {k: n for k, n in counts_v.items()
                     if k not in TIMED_PATHS and n > MAX_DELAY_PROBES_PER_POINT}
            check(not extra,
                  f"V: no other point got more than {MAX_DELAY_PROBES_PER_POINT} delay payloads "
                  f"(observed {extra or 'none'}; all paths {counts_v or 'none'})")
            check(sum(counts_v.get(p, 0) for p in ("/orders", "/ping")) > 0,
                  f"V: the delay payloads really reached the target (per-path {counts_v or 'none'})")

            section("the patched twin yields none of the three")
            iss_p, seq_p = run_blind(op, p)
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
