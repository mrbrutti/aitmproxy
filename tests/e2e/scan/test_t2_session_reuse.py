#!/usr/bin/env python3
# e2e: tier=T1 surface=scan needs=http
"""scan/t2_session_reuse -- AC T2-4: after a REAL login through the proxy
(`POST /login` -> 302 + `Set-Cookie: session=...`) and one authenticated
`GET /account?tab=overview` through the proxy, `scan.session.preview` names the
`session` cookie (names only, never the value) and a `scan.start` with
`session.mode: observed` finds the authenticated-only seeded reflection behind
`/account` (a `REFLECTED_XSS_CLASSES` class, `location.path == "/account"`, `kind == "query"`,
`name == "tab"`); a second job with `session.mode: none` never reaches it.

Observers: the target's control log (`/log/http`): with the observed session the
scanner's `/account` requests return `status == 200` carrying `cookie_names`
including `session`; with `session.mode: none` every `/account` request is a 302.

SKIP 77: serve binary missing, a missing `scan.start`/`scan.status`/`scan.issues`/
`scan.session.preview` verb, or no `http` lane in `scan.checks`.
"""
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.proxyutil import via_proxy  # noqa: E402
from aitm_e2e.scan import (  # noqa: E402
    REFLECTED_XSS_CLASSES,
    ScanTarget,
    issues,
    require_lane,
    require_verbs,
    scan_call,
    start_job,
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


def account_issues(xs: list[dict]) -> list[dict]:
    return [i for i in xs if (i.get("location") or {}).get("path") == "/account"]


def reflected(rows: list[dict]) -> list[dict]:
    """The reflected-XSS issues, selected client-side on the pinned class token."""
    return [i for i in rows if i.get("class") in REFLECTED_XSS_CLASSES]


def main() -> None:
    work = tempfile.mkdtemp(prefix="aitm-e2e-t2-session-")
    try:
        with ScanTarget("vulnerable") as V:
            cfg = CoreConfig(proxy_port=free_port(), scope_entries=[V.authority],
                             findings_dir=os.path.join(work, "findings"))
            with Aitm.server(cfg) as core:
                op = BusClient.operator(core)
                require_verbs(op, "scan.start", "scan.status", "scan.issues", "scan.session.preview")
                require_lane(op, "http")
                proxy = cfg.proxy_port

                section("real login + authenticated GET /account through the proxy")
                sid = login_via_proxy(proxy, V.base)
                cookie = {"Cookie": f"session={sid}"}
                r = via_proxy(proxy, "GET", V.base + "/account?tab=overview", headers=cookie)
                check(r.status == 200, f"GET /account?tab=overview with the session -> 200 (got {r.status})")
                check("<h2>Account: overview</h2>" in r.text, "the authenticated tab is rendered")
                r = via_proxy(proxy, "GET", V.base + "/account?tab=overview")
                check(r.status == 302, f"GET /account without the session -> 302 (got {r.status})")

                section("scan.session.preview names the cookie, never the value")
                prev = scan_call(op, "operator", "scan.session.preview", {"target": V.base})
                check(prev.get("cookies") == ["session"], f"cookies == ['session'] ({prev.get('cookies')})")
                check(sid not in json.dumps(prev), "the session value appears nowhere in the preview")
                canary = prev.get("canary") or {}
                check(canary.get("kind") == "flow" and canary.get("method") == "GET"
                      and canary.get("path") == "/account",
                      f"canary is the authenticated GET /account flow ({canary})")

                section("job 1: session.mode observed finds the /account reflection")
                seq0 = V.logs.reset()
                job1 = start_job(op, "operator", target=V.base,
                                 overrides={"session": {"mode": "observed"}})["job"]
                st1 = wait_terminal(op, "operator", job1, timeout=900)
                check(st1.get("state") == "done", f"job 1 ended done (state={st1.get('state')!r}, "
                                                  f"stopped_reason={st1.get('stopped_reason')!r})")
                sess = st1.get("session") or {}
                check(sess.get("reused") is True, f"status.session.reused is true ({sess})")
                check(sess.get("lost") is False, f"status.session.lost is false ({sess})")
                xs1 = account_issues(reflected(issues(op, "operator", job=job1)))
                ok(f"job 1: /account reflected-xss issues = "
                   f"{[(i['location'].get('kind'), i['location'].get('name')) for i in xs1]}")
                check(any(i["location"].get("kind") == "query" and i["location"].get("name") == "tab" for i in xs1),
                      "job 1: reflected-xss issue on /account query param tab")
                check(all(i["location"].get("method") in (None, "GET") for i in xs1),
                      "job 1: the /account issue is on the GET route")

                section("observer: job 1 reached /account authenticated")
                acct1 = [e for e in V.logs.scanner_requests(seq0) if e.get("path") == "/account"]
                auth200 = [e for e in acct1 if e.get("status") == 200 and "session" in (e.get("cookie_names") or [])]
                check(bool(acct1), f"V log shows scanner /account requests ({len(acct1)})")
                check(bool(auth200), f"V log shows /account requests with status 200 carrying the session cookie "
                                     f"({len(auth200)} of {len(acct1)})")
                check(all("cookie" not in e and "authorization" not in e for e in acct1),
                      "the target log stores no raw cookie/authorization key")

                section("job 2: session.mode none never reaches /account")
                seq1 = V.logs.reset()
                job2 = start_job(op, "operator", target=V.base,
                                 overrides={"session": {"mode": "none"}})["job"]
                st2 = wait_terminal(op, "operator", job2, timeout=900)
                check(st2.get("state") == "done", f"job 2 ended done (state={st2.get('state')!r})")
                sess2 = st2.get("session")
                check(sess2 is None or sess2.get("reused") is False,
                      f"job 2 did not reuse a session ({sess2})")
                xs2 = account_issues(issues(op, "operator", job=job2))
                check(not xs2, f"job 2: no issue on /account ({len(xs2)})")
                acct2 = [e for e in V.logs.scanner_requests(seq1) if e.get("path") == "/account"]
                check(bool(acct2), f"V log shows job 2 requested /account ({len(acct2)})")
                statuses = sorted({e.get("status") for e in acct2})
                check(all(e.get("status") == 302 for e in acct2),
                      f"job 2: every /account request in the log is a 302 (statuses seen: {statuses})")
                check(not any("session" in (e.get("cookie_names") or []) for e in acct2),
                      "job 2: no /account request carried a session cookie")
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
