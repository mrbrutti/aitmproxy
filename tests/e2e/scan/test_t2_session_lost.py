#!/usr/bin/env python3
# e2e: tier=T1 surface=scan needs=http
"""scan/t2_session_lost -- AC T2-5: with a real observed session, when the target
invalidates it mid-scan (seeded `GET /logout-after?n=20`: the session dies after
20 further authenticated `GET /account` requests) the job stops with
`stopped_reason == "session_lost"`, `session.lost == true` and `session.reused == true`.

Capture order matters (parent spec D7: the canary replays the NEWEST captured
authenticated GET): login -> `GET /account?tab=overview` -> `GET /logout-after?n=20`
-> `GET /account?tab=overview` again, so the canary is `/account` (asserted from
`scan.status`), not `/logout-after` (which would re-arm the countdown). The arm
allows N further authenticated `GET /account`s, the one that drives the counter to
0 is still answered 200 and the 302 starts on the next (`SessionStore::touch`); the
cell's own second GET consumes one, so the seed alone leaves N - 1 = 19 for the
scanner. But the scanner also replays the captured `GET /logout-after?n=20` with the
session (crawl / baseline), which RE-ARMS the countdown to 20 whenever it runs, and
the scheduler decides when. So the observer derives its expectation inside the
window (`V.logs.reset()` is taken after the cell's own GETs): with no authenticated
`/logout-after` 200 before the first 302, exactly N - 1 authenticated `/account`
200s precede it; otherwise exactly N `/account` 200s lie between the last such
re-arm and the 302 (T2 live run 2 saw 21 = 1 before the re-arm + 20 after).

Observers: the target's control log (`/log/http`): the first `/account` 302 that
carries the session cookie comes after the derived count of `/account` 200s and
after >= 20 requests carrying the session cookie overall.

SKIP 77: serve binary missing, a missing `scan.start`/`scan.status` verb, or no
`http` lane in `scan.checks`.
"""
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
from aitm_e2e.proxyutil import via_proxy  # noqa: E402
from aitm_e2e.scan import (  # noqa: E402
    boot_target,
    login_via_proxy,
    require_lane,
    require_verbs,
    start_job,
    wait_terminal,
)

# The browser crawl drives a real obscura engine, so a T2 job runs far longer
# than the 600 s the engine-only cells need.
JOB_TIMEOUT = 900.0

ARMED = 20


def with_session(e: dict) -> bool:
    return "session" in (e.get("cookie_names") or [])


def main() -> None:
    work = tempfile.mkdtemp(prefix="aitm-e2e-t2-session-lost-")
    try:
        with boot_target("vulnerable") as V:
            cfg = CoreConfig(proxy_port=free_port(), scope_entries=[V.authority],
                             findings_dir=os.path.join(work, "findings"))
            with Aitm.server(cfg) as core:
                op = BusClient.operator(core)
                require_verbs(op, "scan.start", "scan.status")
                require_lane(op, "http")
                proxy = cfg.proxy_port

                section("real login, authenticated GET /account, arm /logout-after, GET /account again")
                try:
                    sid = login_via_proxy(proxy, V.base)
                except RuntimeError as e:
                    fail(str(e))
                ok("POST /login through the proxy set a 32-hex HttpOnly session cookie")
                cookie = {"Cookie": f"session={sid}"}
                r = via_proxy(proxy, "GET", V.base + "/account?tab=overview", headers=cookie)
                check(r.status == 200, f"GET /account?tab=overview with the session -> 200 (got {r.status})")
                r = via_proxy(proxy, "GET", V.base + f"/logout-after?n={ARMED}", headers=cookie)
                check(r.status == 200 and r.text == f'{{"armed":{ARMED}}}',
                      f"GET /logout-after?n={ARMED} -> {{\"armed\":{ARMED}}} (got {r.status} {r.text[:40]!r})")
                r = via_proxy(proxy, "GET", V.base + "/account?tab=overview", headers=cookie)
                check(r.status == 200, "GET /account?tab=overview again -> 200 (newest authenticated GET; 19 of 20 left)")

                section("scan.start with session.mode observed")
                seq0 = V.logs.reset()
                job = start_job(op, "operator", target=V.base,
                                overrides={"session": {"mode": "observed"}})["job"]
                st = wait_terminal(op, "operator", job, timeout=JOB_TIMEOUT)
                ok(f"job {job} ended state={st.get('state')!r} phase={st.get('phase')!r} "
                   f"probes.sent={(st.get('probes') or {}).get('sent')}")
                check(st.get("state") in ("done", "failed", "cancelled"), "job reached a terminal state")
                check(st.get("stopped_reason") == "session_lost",
                      f"stopped_reason == session_lost (got {st.get('stopped_reason')!r})")
                sess = st.get("session") or {}
                check(sess.get("reused") is True, f"session.reused is true ({sess})")
                check(sess.get("lost") is True, f"session.lost is true ({sess})")
                canary = sess.get("canary") or {}
                check(canary.get("kind") == "flow" and canary.get("path") == "/account",
                      f"the canary replayed the newest authenticated GET /account ({canary})")

                section("observer: the target dropped the session after the armed count")
                reqs = sorted(V.logs.scanner_requests(seq0), key=lambda e: int(e.get("seq", 0)))
                acct = [e for e in reqs if e.get("path") == "/account" and with_session(e)]
                first_302 = next((i for i, e in enumerate(acct) if e.get("status") == 302), None)
                check(first_302 is not None,
                      f"V log shows a /account 302 carrying the session cookie ({len(acct)} authenticated /account requests)")
                before = acct[:first_302] if first_302 is not None else []
                n200 = sum(1 for e in before if e.get("status") == 200)
                first_seq = int(acct[first_302].get("seq", 0)) if first_302 is not None else 0
                # The scanner may replay the captured `GET /logout-after?n=20` with the
                # session, which re-arms the countdown to ARMED; derive the expectation
                # from the window: no re-arm -> the seed's own ARMED - 1 (the cell's
                # second GET used one); re-arm(s) -> exactly ARMED /account 200s after
                # the last re-arm. The request that reaches 0 is still a 200.
                rearms = [e for e in reqs if e.get("path") == "/logout-after" and with_session(e)
                          and e.get("status") == 200 and int(e.get("seq", 0)) < first_seq]
                if rearms:
                    last_rearm_seq = int(rearms[-1].get("seq", 0))
                    after_rearm = [e for e in before if int(e.get("seq", 0)) > last_rearm_seq]
                    n_after = sum(1 for e in after_rearm if e.get("status") == 200)
                    check(n_after == ARMED and len(after_rearm) == n_after,
                          f"exactly {ARMED} authenticated /account 200s lie between the last "
                          f"/logout-after re-arm and the first 302 ({len(rearms)} re-arm(s); "
                          f"got {n_after} 200s of {len(after_rearm)}; {n200} 200s in the whole window)")
                else:
                    check(n200 == ARMED - 1 and len(before) == n200,
                          f"exactly {ARMED - 1} authenticated /account 200s precede the first 302 "
                          f"(no re-arm in the window; got {n200} 200s of {len(before)})")
                total_auth_before = sum(1 for e in reqs if with_session(e) and int(e.get("seq", 0)) < first_seq)
                check(total_auth_before >= ARMED,
                      f">= {ARMED} requests carrying the session cookie precede the 302 (got {total_auth_before})")
                check(all("cookie" not in e and "authorization" not in e for e in reqs),
                      "the target log stores no raw cookie/authorization key")
                after_302 = [e for e in acct[first_302 + 1:]] if first_302 is not None else []
                check(all(e.get("status") == 302 for e in after_302),
                      f"every later authenticated /account request is also a 302 ({len(after_302)} after the first)")
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
