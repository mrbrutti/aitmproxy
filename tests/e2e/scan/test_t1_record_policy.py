#!/usr/bin/env python3
# e2e: tier=T1 surface=scan needs=http
"""scan/test_t1_record_policy -- AC T1-9: the default `issues_only` record policy.

Store-diff rule: snapshot the flow ids BEFORE `scan.start`, run `standard` on V, and
look only at the rows the job added. Every added row for V's authority that is not
the cell's own real request carries `scan:<job>` in `marks`; rows marked `crawl` also
carry `scan:<job>`; every scan-marked non-crawl row carries an `issue:<id>` mark (no
probe flow without an issue is present); the store holds FAR fewer rows than the
target's control log counted scanner requests; and a REAL request the cell sends
through the proxy during the job (`GET /preview?msg=real-<RUN>`) is still listed and
carries no `scan:` mark.

Observers: the target's own request log (count) vs the core's flow store; the real
flow the cell itself drove. Own target + own core on free ports; tokens never printed.

SKIP 77: `aitm-testtarget-serve` not built; the v2 verbs absent (`missing verb ...`).
"""
from __future__ import annotations

import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.proxyutil import via_proxy  # noqa: E402
from aitm_e2e.scan import (  # noqa: E402
    TERMINAL_STATES,
    boot_target,
    require_verbs,
    scan_call,
    start_job,
    until,
    wait_terminal,
)

JOB_TIMEOUT = 600.0
# Wait at most this long for the job to leave the crawl phase before sending the
# real request (the browser crawl marks store additions around its navigations,
# spec D8; sending after it keeps the "real flow is unmarked" assertion honest).
CRAWL_WAIT = 30.0
# How long the store may take to re-record a probe flow's `issue:<id>` mark.
SETTLE_TIMEOUT = 10.0


def flow_rows(op) -> list[dict]:
    doc = op.call("flow.table")
    rows = doc.get("flows") if isinstance(doc, dict) else None
    return [r for r in (rows or []) if isinstance(r, dict)]


def marks_of(row: dict) -> list[str]:
    return [m for m in (row.get("marks") or []) if isinstance(m, str)]


def main() -> int:
    run = uuid.uuid4().hex[:10]
    marker = f"real-{run}"
    target = core = op = None
    try:
        section("arrange: vulnerable target + own core on free ports")
        target = boot_target("vulnerable")
        cfg = CoreConfig(proxy_port=free_port(), browser_proxy_port=free_port(),
                         scope_entries=[target.authority])
        core = Aitm.server(cfg)
        op = BusClient.operator(core)
        require_verbs(op, "scan.start", "scan.status")
        seq0 = target.logs.reset()
        before = {r.get("id") for r in flow_rows(op)}
        ok(f"store snapshot before the job: {len(before)} flow(s)")

        section("act: standard on V, one REAL request through the proxy during the job")
        r = start_job(op, "operator", target=target.base)
        job = r["job"]
        scan_mark = f"scan:{job}"
        deadline = time.monotonic() + CRAWL_WAIT
        st = r.get("status") or {}
        while time.monotonic() < deadline:
            st = scan_call(op, "operator", "scan.status", {"job": job})
            if st.get("state") in TERMINAL_STATES or st.get("phase") not in ("queued", "crawling"):
                break
            time.sleep(0.5)
        state_at_send, phase_at_send = st.get("state"), st.get("phase")
        resp = via_proxy(cfg.proxy_port, "GET", f"{target.base}/preview?msg={marker}")
        check(resp.status == 200 and marker in resp.text,
              f"the real request rode the proxy to V and echoed {marker} (status {resp.status})")
        check(state_at_send not in TERMINAL_STATES,
              f"the real request was sent while the job was live (state={state_at_send!r}, phase={phase_at_send!r})")
        final = wait_terminal(op, "operator", job, timeout=JOB_TIMEOUT)
        check(final.get("state") == "done", f"job {job} finished done (got {final.get('state')!r}, "
              f"stopped_reason={final.get('stopped_reason')!r})")
        # The store re-records a probe flow's marks as its issue lands: poll until
        # every non-crawl job flow carries an `issue:<id>` mark instead of sleeping a
        # fixed second. The assertions below still judge the result on their own.
        def issue_marks_settled() -> bool:
            fresh = [r for r in flow_rows(op) if r.get("id") not in before
                     and r.get("authority") == target.authority
                     and marker not in str(r.get("path") or "")
                     and "crawl" not in marks_of(r)]
            return bool(fresh) and all(
                any(m.startswith("issue:") for m in marks_of(r)) for r in fresh)

        until(issue_marks_settled, SETTLE_TIMEOUT)

        section("assert: store diff vs the target's request log")
        rows = [r for r in flow_rows(op) if r.get("id") not in before]
        v_rows = [r for r in rows if r.get("authority") == target.authority]
        real_rows = [r for r in v_rows if marker in str(r.get("path") or "")]
        check(len(real_rows) == 1, f"the real {marker} flow is listed exactly once ({len(real_rows)})")
        real_marks = marks_of(real_rows[0]) if real_rows else []
        check(not any(m.startswith("scan:") for m in real_marks) and "crawl" not in real_marks,
              f"the real flow carries no scan:/crawl mark (marks={real_marks})")
        scan_rows = [r for r in v_rows if marker not in str(r.get("path") or "")]
        check(len(scan_rows) >= 1, f"the job added flows for V to the store ({len(scan_rows)})")
        unmarked = [(r.get("id"), r.get("path"), marks_of(r)) for r in scan_rows if scan_mark not in marks_of(r)]
        check(not unmarked, f"every job-added V flow carries {scan_mark} (offenders: {unmarked[:5]})")
        crawl_rows = [r for r in scan_rows if "crawl" in marks_of(r)]
        check(all(scan_mark in marks_of(r) for r in crawl_rows),
              f"every `crawl` row also carries {scan_mark} ({len(crawl_rows)} crawl row(s))")
        probe_rows = [r for r in scan_rows if "crawl" not in marks_of(r)]
        # V is vulnerable and `standard` finds issues there (T1-3 demands an `issue`
        # push line), so issues_only must have kept at least one evidence probe: without
        # this the `issue:<id>` assertion below would pass over an empty list.
        check(len(probe_rows) >= 1,
              f"at least one issue-evidence probe flow was kept by issues_only ({len(probe_rows)} non-crawl scan row(s))")
        no_issue = [(r.get("id"), r.get("path")) for r in probe_rows
                    if not any(m.startswith("issue:") for m in marks_of(r))]
        # Amendment 79 (T2 follow-up): the lane crate's /robots.txt and /sitemap.xml
        # seed fetches bypass the recorder, so no seed row can appear here; the
        # assertion below is hard on both lane sources.
        check(not no_issue, f"no probe flow without an issue: every non-crawl scan row carries issue:<id> "
              f"(offenders: {no_issue[:5]})")
        n_target = len(target.logs.scanner_requests(seq0))
        check(n_target > 0, f"the target counted {n_target} request(s) since the reset")
        check(len(rows) < n_target, f"the store holds far fewer job rows ({len(rows)}) than the target saw requests ({n_target})")
        probes_sent = int((final.get("probes") or {}).get("sent") or 0)
        print(f"note: probes.sent={probes_sent} target_requests={n_target} store_rows={len(rows)} "
              f"(crawl={len(crawl_rows)}, issue-evidence={len(probe_rows)})", flush=True)
        foreign = sorted({str(r.get("authority")) for r in rows if r.get("authority") != target.authority})
        print(f"note: job-window rows for other authorities: {foreign or 'none'}", flush=True)
        ok("PASS: issues_only record policy holds; real traffic during the scan stays listed and unmarked")
        return 0
    finally:
        if op:
            op.close()
        if core:
            core.stop()
        if target:
            target.stop()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
