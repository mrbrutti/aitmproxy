#!/usr/bin/env python3
# e2e: tier=T1 surface=scan needs=http
"""scan/t2_no_secret_leak -- AC T2-6: with a real observed session (cookie value S
from a real `POST /login` through the proxy) and a real proxied `GET /whoami`
carrying `Authorization: Bearer e2e-auth-<hex>` (value A), a `scan.start` with
`session.mode: observed` leaks neither S nor A anywhere the harness can see: the
results of `scan.status`, `scan.issues` (every page), every `scan.issue`,
`scan.sitemap` (every page), `scan.session.preview`, every push line a second
subscribed BusClient received, every file under `findings_dir` (issues, jobs,
profiles, findings, PoCs) and the core's stderr/stdout.

Observers: the text the harness captured (the grep is over everything), plus the
target's control log showing the scanner really carried the session (so the
"no leak" is of material that was in use, not of material never applied).

SKIP 77: serve binary missing, a missing `scan.start`/`scan.status`/`scan.issues`/
`scan.issue`/`scan.sitemap`/`scan.session.preview` verb, or no `http` lane in
`scan.checks`.
"""
import json
import os
import re
import secrets
import shutil
import sys
import tempfile
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.proxyutil import via_proxy  # noqa: E402
from aitm_e2e.scan import (  # noqa: E402
    ScanTarget,
    collect_push,
    issue,
    issues,
    require_lane,
    require_verbs,
    scan_call,
    start_job,
    subscribe,
    wait_terminal,
)


def login_via_proxy(proxy: int, base: str) -> str:
    """`POST /login` through the proxy; returns the 32-hex session id (never printed)."""
    r = via_proxy(proxy, "POST", base + "/login",
                  headers={"Content-Type": "application/x-www-form-urlencoded"},
                  body=b"user=alice&pass=wonderland")
    check(r.status == 302, f"POST /login through the proxy -> 302 (got {r.status})")
    headers = {k.lower(): v for k, v in r.headers.items()}
    m = re.match(r"session=([0-9a-f]{32}); HttpOnly; Path=/$", headers.get("set-cookie") or "")
    if not m:
        fail("login did not answer with `Set-Cookie: session=<32 hex>; HttpOnly; Path=/`")
    ok("login set a 32-hex HttpOnly session cookie")
    return m.group(1)


def sitemap_pages(op, job: str) -> list[dict]:
    pages: list[dict] = []
    cursor = None
    seen: set[str] = set()
    while True:
        args: dict = {"job": job, "limit": 1024}
        if cursor:
            args["cursor"] = cursor
        page = scan_call(op, "operator", "scan.sitemap", args)
        pages.append(page)
        cursor = page.get("next_cursor")
        if not cursor or cursor in seen:
            return pages
        seen.add(cursor)


def files_under(root: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for dirpath, _dirs, names in os.walk(root):
        for name in names:
            path = os.path.join(dirpath, name)
            try:
                out[path] = Path(path).read_bytes().decode("utf-8", errors="replace")
            except OSError as e:
                out[path] = f"<unreadable: {e}>"
    return out


def main() -> None:
    work = tempfile.mkdtemp(prefix="aitm-e2e-t2-leak-")
    findings_dir = os.path.join(work, "findings")
    try:
        with ScanTarget("vulnerable") as V:
            cfg = CoreConfig(proxy_port=free_port(), scope_entries=[V.authority], findings_dir=findings_dir)
            with Aitm.server(cfg) as core:
                op = BusClient.operator(core)
                require_verbs(op, "scan.start", "scan.status", "scan.issues", "scan.issue",
                              "scan.sitemap", "scan.session.preview")
                require_lane(op, "http")
                proxy = cfg.proxy_port
                sub = subscribe(BusClient.operator(core))

                section("real session material through the proxy (values never printed)")
                S = login_via_proxy(proxy, V.base)
                cookie = {"Cookie": f"session={S}"}
                r = via_proxy(proxy, "GET", V.base + "/account?tab=overview", headers=cookie)
                check(r.status == 200, f"GET /account?tab=overview with the session -> 200 (got {r.status})")
                bearer = "e2e-auth-" + secrets.token_hex(12)
                A = "Bearer " + bearer
                r = via_proxy(proxy, "GET", V.base + "/whoami", headers={"Authorization": A, **cookie})
                check(r.status == 200, f"GET /whoami with Authorization -> 200 (got {r.status})")
                ok(f"S is {len(S)} chars, A is {len(A)} chars")

                section("preview + observed-session job, with a second subscriber collecting push")
                prev = scan_call(op, "operator", "scan.session.preview", {"target": V.base})
                check("session" in (prev.get("cookies") or []), f"preview names the session cookie ({prev.get('cookies')})")
                seq0 = V.logs.reset()
                job = start_job(op, "operator", target=V.base,
                                overrides={"session": {"mode": "observed"}})["job"]
                lines: list[dict] = []
                collector = threading.Thread(
                    target=lambda: lines.extend(collect_push(sub, job, timeout=900)), daemon=True)
                collector.start()
                st = wait_terminal(op, "operator", job, timeout=900)
                collector.join(timeout=30)
                ok(f"job {job} ended state={st.get('state')!r} stopped_reason={st.get('stopped_reason')!r}; "
                   f"{len(lines)} push lines collected")
                sess = st.get("session") or {}
                check(sess.get("reused") is True, f"the session was reused (so the material was in play) ({sess})")
                check(bool(lines) and lines[-1].get("event") in ("finished", "cancelled", "failed"),
                      f"push ended with a terminal event ({lines[-1].get('event') if lines else None})")
                acct = [e for e in V.logs.scanner_requests(seq0)
                        if e.get("path") == "/account" and "session" in (e.get("cookie_names") or [])]
                check(bool(acct), f"target log: the scanner carried the session cookie to /account ({len(acct)})")

                section("gather everything the harness can see")
                corpus: dict[str, str] = {"scan.status": json.dumps(st)}
                all_issues = issues(op, "operator", job=job)
                corpus["scan.issues"] = json.dumps(all_issues)
                for summary in all_issues:
                    iid = summary.get("id")
                    if isinstance(iid, str):
                        corpus[f"scan.issue {iid}"] = json.dumps(issue(op, "operator", iid))
                corpus["scan.sitemap"] = json.dumps(sitemap_pages(op, job))
                corpus["scan.session.preview"] = json.dumps(
                    scan_call(op, "operator", "scan.session.preview", {"target": V.base}))
                corpus["push lines"] = json.dumps(lines)
                files = files_under(findings_dir)
                corpus.update(files)
                corpus["core stderr"] = core.stderr_text()
                corpus["core stdout"] = core.stdout_text()
                ok(f"{len(all_issues)} issues, {len(files)} files under findings_dir, "
                   f"{sum(len(v) for v in corpus.values())} chars gathered")
                check(len(files) >= 1, "findings_dir holds at least one file written by the job")

                section("neither the session value nor the Authorization value appears anywhere")
                leaks_s = sorted(k for k, v in corpus.items() if S in v)
                leaks_a = sorted(k for k, v in corpus.items() if A in v or bearer in v)
                check(not leaks_s, f"session cookie value absent from every result, push line, file and log (in: {leaks_s})")
                check(not leaks_a, f"Authorization value absent from every result, push line, file and log (in: {leaks_a})")
                sub.close()
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
