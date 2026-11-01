#!/usr/bin/env python3
# e2e: tier=T1 surface=scan needs=http
"""scan/test_t1_issues -- AC T1-7: dedupe, occurrences, and a persisted status.

Two `standard` jobs on the vulnerable target (V) produce exactly ONE reflected-XSS
issue for the `/search` `q` query point; its `id` is the same after both runs (the
dedupe key of spec D6 is stable), `occurrences >= 2` and grows across runs,
`last_seen >= first_seen`; no two issues share `(class, path_template, kind, name)`.
`scan.issue.update` to `false_positive` is then read back by a NEW core booted on the
same `findings_dir` after the first core stopped.

Observers: the restarted core reading the issue store from disk, a file under
`findings_dir` naming the issue, and the target's own control log (the jobs really
hit `/search`). Own target + own cores on free ports; tokens never printed.

SKIP 77: `aitm-testtarget-serve` not built; the v2 verbs absent (`missing verb ...`).
Class token: the pinned reflection vocabulary is `aitm_e2e.scan.REFLECTED_XSS_CLASSES`
(`reflected-xss`); the cell filters client-side and prints the token it saw.
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.scan import (  # noqa: E402
    REFLECTED_XSS_CLASSES,
    boot_target,
    issue,
    issues,
    require_verbs,
    scan_call,
    start_job,
    wait_terminal,
)

JOB_TIMEOUT = 600.0


def xss_on_search(rows: list[dict]) -> list[dict]:
    """The issues for the `/search` `q` query point of a reflection class."""
    out = []
    for i in rows:
        loc = i.get("location") or {}
        if i.get("class") in REFLECTED_XSS_CLASSES and loc.get("path") == "/search" \
                and loc.get("kind") == "query" and loc.get("name") == "q":
            out.append(i)
    return out


def dedupe_key(i: dict) -> tuple:
    loc = i.get("location") or {}
    return (i.get("class"), loc.get("path_template"), loc.get("kind"), loc.get("name"))


def files_mentioning(root: str, needle: str) -> list[str]:
    hits = []
    for dirpath, _dirs, names in os.walk(root):
        for n in names:
            p = os.path.join(dirpath, n)
            try:
                if needle in Path(p).read_text(encoding="utf-8", errors="replace"):
                    hits.append(os.path.relpath(p, root))
            except OSError:
                pass
    return sorted(hits)


def run_standard(op, target_base: str) -> dict:
    r = start_job(op, "operator", target=target_base)
    job = r["job"]
    st = wait_terminal(op, "operator", job, timeout=JOB_TIMEOUT)
    check(st.get("state") == "done", f"job {job} finished with state done (got {st.get('state')!r}, "
          f"stopped_reason={st.get('stopped_reason')!r})")
    check(st.get("profile_name") == "standard", f"job {job} ran the `standard` profile (got {st.get('profile_name')!r})")
    return st


def main() -> int:
    work = tempfile.mkdtemp(prefix="aitm-e2e-t1-issues-")
    findings_dir = os.path.join(work, "findings")
    os.makedirs(findings_dir, exist_ok=True)
    target = core = core2 = op = op2 = None
    try:
        section("arrange: vulnerable target + own core on free ports")
        target = boot_target("vulnerable")
        cfg = CoreConfig(proxy_port=free_port(), scope_entries=[target.authority], findings_dir=findings_dir)
        core = Aitm.server(cfg)
        op = BusClient.operator(core)
        require_verbs(op, "scan.start", "scan.status", "scan.issues", "scan.issue", "scan.issue.update")
        seq0 = target.logs.reset()

        section("run 1: standard on V")
        t_start = int(time.time() * 1000)
        run_standard(op, target.base)
        iss1 = issues(op, "operator")
        m1 = xss_on_search(iss1)
        check(len(m1) == 1, f"exactly one reflection issue for /search?q after run 1 (got {len(m1)}; "
              f"{len(iss1)} issue(s) total)")
        x1 = m1[0]
        print(f"note: class token on this build = {x1.get('class')!r}, check_id = {x1.get('check_id')!r}", flush=True)
        occ1 = int(x1.get("occurrences") or 0)
        check(occ1 >= 1, f"run 1 occurrences >= 1 (got {occ1})")

        section("run 2: standard on V again -> same issue id, occurrences grew")
        run_standard(op, target.base)
        iss2 = issues(op, "operator")
        m2 = xss_on_search(iss2)
        check(len(m2) == 1, f"still exactly one reflection issue for /search?q after run 2 (got {len(m2)})")
        x2 = m2[0]
        check(x2["id"] == x1["id"], f"dedupe key is stable across runs: same id {x1['id']} (run 2 gave {x2['id']})")
        occ2 = int(x2.get("occurrences") or 0)
        check(occ2 >= 2, f"occurrences >= 2 after two runs (got {occ2})")
        check(occ2 > occ1, f"occurrences grew across runs ({occ1} -> {occ2})")
        check(int(x2.get("last_seen") or 0) >= int(x2.get("first_seen") or 0),
              f"last_seen >= first_seen ({x2.get('last_seen')} >= {x2.get('first_seen')})")
        check(int(x2.get("first_seen") or 0) >= t_start - 1000,
              "first_seen is from this cell's runs (not a stale store)")
        keys = [dedupe_key(i) for i in iss2]
        dups = sorted({k for k in keys if keys.count(k) > 1})
        check(not dups, f"no two issues share (class, path_template, kind, name) (dups: {dups})")

        section("observer: the target saw the jobs on /search")
        reqs = target.logs.scanner_requests(seq0)
        search_hits = [e for e in reqs if str(e.get("path") or "").startswith("/search")]
        check(len(search_hits) >= 2, f"target control log shows >= 2 scanner requests to /search "
              f"({len(search_hits)} of {len(reqs)} requests since reset)")

        section("scan.issue.update -> false_positive")
        upd = scan_call(op, "operator", "scan.issue.update",
                        {"id": x1["id"], "status": "false_positive", "note": "e2e"})
        check(isinstance(upd, dict) and upd.get("status") == "false_positive",
              f"scan.issue.update returned status false_positive (got {upd.get('status') if isinstance(upd, dict) else upd!r})")
        check(upd.get("note") == "e2e", f"the note round-trips (got {upd.get('note')!r})")
        on_disk = files_mentioning(findings_dir, x1["id"])
        check(bool(on_disk), f"a file under findings_dir names the issue {x1['id']} ({on_disk[:3]})")

        section("restart: a new core on the same findings_dir reads the status back")
        op.close()
        op = None
        core.stop()
        core = None
        cfg2 = CoreConfig(proxy_port=free_port(), scope_entries=[target.authority], findings_dir=findings_dir)
        core2 = Aitm.server(cfg2)
        op2 = BusClient.operator(core2)
        got = issue(op2, "operator", x1["id"])
        check(isinstance(got, dict) and got.get("id") == x1["id"], f"scan.issue {x1['id']} resolves after the restart")
        check(got.get("status") == "false_positive",
              f"status == false_positive after the core restart (got {got.get('status')!r})")
        check(got.get("note") == "e2e", f"note persisted across the restart (got {got.get('note')!r})")
        check(int(got.get("occurrences") or 0) == occ2,
              f"occurrences persisted across the restart ({got.get('occurrences')} == {occ2})")
        ok("PASS: one issue per point, stable id, occurrences counted, false_positive persisted on disk")
        return 0
    finally:
        for b in (op, op2):
            if b:
                b.close()
        for c in (core, core2):
            if c:
                c.stop()
        if target:
            target.stop()
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
