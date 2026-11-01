#!/usr/bin/env python3
# e2e: tier=T1 surface=scan needs=http
"""scan/test_t1_finding_link -- AC T1-10: issue <-> FindingRecord link via PocHint.

With `findings.dir` set, a `standard` job on V yields a reflected-XSS issue on
`/search` whose `finding_id` is non-null, and a file under `findings_dir` whose text
contains that `finding_id` AND `passed: true` (the recorded `FindingRecord`'s
`reproduction.passed`). An issue from a check WITHOUT a PocHint (a `technique:
passive` check per `scan.checks`; else any class outside the two hinted interim
natives) has `finding_id == None` and no record. On P: no reflection issue on
`/search` and no NEW finding file mentions `/search`.

Observers: files on disk under `findings_dir`, `scan.checks` for which checks are
passive, the target control logs. Own targets + own core; tokens never printed.

SKIP 77: `aitm-testtarget-serve` not built; the v2 verbs absent (`missing verb ...`).
Class token: the pinned reflection vocabulary is `aitm_e2e.scan.REFLECTED_XSS_CLASSES`
(`reflected-xss`); the cell filters client-side and prints the token it saw.
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.scan import (  # noqa: E402
    REFLECTED_XSS_CLASSES,
    boot_target,
    issues,
    require_verbs,
    scan_call,
    start_job,
    wait_terminal,
)

HINTED_INTERIM = set(REFLECTED_XSS_CLASSES) | {"open-redirect"}
# Origin-level classes raised by checks that carry no PocHint (the coordinator's list,
# 2026-11-01, beside the D3 passive row's `missing-hsts`). The hint-less fallback below
# accepts them as hint-less issues: they must carry `finding_id == None`.
ORIGIN_LEVEL_CLASSES = frozenset({
    "missing-hsts",
    "missing-security-headers",
    "risky-http-methods",
    "exposed-path",
    "cors",
    "information-disclosure",
})
JOB_TIMEOUT = 600.0


def xss_on_search(rows: list[dict]) -> list[dict]:
    return [i for i in rows if i.get("class") in REFLECTED_XSS_CLASSES
            and (i.get("location") or {}).get("path") == "/search"]


def finding_files(root: str) -> dict[str, str]:
    """relative path -> text, for every regular file under `root`."""
    out: dict[str, str] = {}
    for dirpath, _dirs, names in os.walk(root):
        for n in names:
            p = os.path.join(dirpath, n)
            try:
                out[os.path.relpath(p, root)] = Path(p).read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass
    return out


def run_standard(op, base: str) -> tuple[str, dict]:
    r = start_job(op, "operator", target=base)
    job = r["job"]
    st = wait_terminal(op, "operator", job, timeout=JOB_TIMEOUT)
    check(st.get("state") == "done", f"job {job} on {base} finished done (got {st.get('state')!r}, "
          f"stopped_reason={st.get('stopped_reason')!r})")
    return job, st


def main() -> int:
    work = tempfile.mkdtemp(prefix="aitm-e2e-t1-finding-link-")
    findings_dir = os.path.join(work, "findings")
    os.makedirs(findings_dir, exist_ok=True)
    v = p = core = op = None
    try:
        section("arrange: V + P targets, own core with findings.dir set")
        v = boot_target("vulnerable")
        p = boot_target("patched")
        cfg = CoreConfig(proxy_port=free_port(), browser_proxy_port=free_port(),
                         scope_entries=[v.authority, p.authority], findings_dir=findings_dir)
        core = Aitm.server(cfg)
        op = BusClient.operator(core)
        require_verbs(op, "scan.start", "scan.status", "scan.issues", "scan.checks")
        checks = scan_call(op, "operator", "scan.checks", {}).get("checks", [])
        passive_ids = {c.get("id") for c in checks if isinstance(c, dict) and c.get("technique") == "passive"}
        seq_v = v.logs.reset()

        section("V: standard -> the /search reflection issue links a passed FindingRecord")
        job_v, _ = run_standard(op, v.base)
        iss_v = issues(op, "operator", job=job_v)
        xs = xss_on_search(iss_v)
        check(len(xs) == 1, f"exactly one reflection issue on /search for the V job (got {len(xs)}; {len(iss_v)} issue(s))")
        x = xs[0]
        print(f"note: class token on this build = {x.get('class')!r}, check_id = {x.get('check_id')!r}, "
              f"confidence = {x.get('confidence')!r}", flush=True)
        fid = x.get("finding_id")
        check(isinstance(fid, str) and fid != "", f"finding_id is non-null on the /search issue (got {fid!r})")
        files_v = finding_files(findings_dir)
        linked = sorted(rel for rel, text in files_v.items() if fid and fid in text and "passed: true" in text)
        check(bool(linked), f"a file under findings_dir contains {fid!r} and `passed: true` ({linked[:3]})")
        check(len(v.logs.scanner_requests(seq_v)) > 0, "the V job really reached the target (control log)")

        section("V: an issue from a check without a PocHint has no finding")
        passive_issues = [i for i in iss_v if i.get("check_id") in passive_ids]
        if passive_issues:
            bad = [(i.get("id"), i.get("class"), i.get("finding_id")) for i in passive_issues if i.get("finding_id") is not None]
            check(not bad, f"{len(passive_issues)} passive issue(s) carry finding_id == None (offenders: {bad[:3]})")
        else:
            hintless = [i for i in iss_v if i.get("class") not in HINTED_INTERIM]
            if hintless:
                origin_level = sorted({str(i.get("class")) for i in hintless
                                       if i.get("class") in ORIGIN_LEVEL_CLASSES})
                print(f"note: {len(hintless)} hint-less issue(s); origin-level classes among them = "
                      f"{origin_level}", flush=True)
                bad = [(i.get("id"), i.get("class"), i.get("finding_id")) for i in hintless if i.get("finding_id") is not None]
                check(not bad, f"{len(hintless)} issue(s) outside the hinted interim classes carry finding_id == None "
                      f"(offenders: {bad[:3]})")
            else:
                print("note: no passive or hint-less issue on V in this run; that half of T1-10 is not exercised here",
                      flush=True)

        section("P: standard -> no reflection issue on /search, no new finding file mentions /search")
        before_p = set(files_v)
        seq_p = p.logs.reset()
        job_p, _ = run_standard(op, p.base)
        iss_p = issues(op, "operator", job=job_p)
        check(not xss_on_search(iss_p), f"no reflection issue on /search for the P job ({len(iss_p)} issue(s) total)")
        files_p = finding_files(findings_dir)
        new_mentioning = sorted(rel for rel, text in files_p.items() if rel not in before_p and "/search" in text)
        check(not new_mentioning, f"no finding file written by the P job mentions /search ({new_mentioning[:3]})")
        p_auth_files = sorted(rel for rel, text in files_p.items() if p.authority in text and "/search" in text)
        check(not p_auth_files, f"no finding file names P's authority together with /search ({p_auth_files[:3]})")
        check(len(p.logs.scanner_requests(seq_p)) > 0, "the P job really reached the patched target (control log)")
        ok("PASS: hinted vulnerable verdict -> passed FindingRecord + finding_id; hint-less -> issue only; P clean")
        return 0
    finally:
        if op:
            op.close()
        if core:
            core.stop()
        for t in (v, p):
            if t:
                t.stop()
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
