#!/usr/bin/env python3
# e2e: tier=T1 surface=scan needs=http
"""scan/t2_mutable_points -- AC T2-3: the seeded header reflection (`GET /whoami`,
`User-Agent` / `X-Forwarded-For`) and cookie reflection (`GET /prefs`, cookie `theme`)
are found on V as `class == "xss"` issues with `location.kind == "header"` on
`/whoami` and `location.kind == "cookie"` on `/prefs`, and NOT found on P, after
real proxied captures of both routes on both origins.

Observers: the target's control log (`/log/http`): the scanner's `/whoami`
requests carry a `user-agent` or `x-forwarded-for` different from the captured
one, and its `/prefs` requests carry `cookie_names == ["theme"]` with a
`cookie_sha256` different from the captured `theme=dark` (the mutation reached
the target: header and cookie points are mutable); P was probed too.

SKIP 77: serve binary missing, a missing `scan.start`/`scan.status`/`scan.issues`
verb, or no `http` lane in `scan.checks` (the T2 lane is not on this build).
"""
import hashlib
import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, free_port, ok, section  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.proxyutil import via_proxy  # noqa: E402
from aitm_e2e.scan import (  # noqa: E402
    ScanTarget,
    issues,
    require_lane,
    require_verbs,
    start_job,
    wait_terminal,
)

UA = "aitm-e2e-ua/1.0"
XFF = "1.2.3.4"
COOKIE = "theme=dark"
COOKIE_SHA16 = hashlib.sha256(COOKIE.encode("utf-8")).hexdigest()[:16]


def capture(proxy: int, base: str) -> None:
    r = via_proxy(proxy, "GET", base + "/whoami", headers={"User-Agent": UA, "X-Forwarded-For": XFF})
    check(r.status == 200, f"GET /whoami through the proxy -> 200 on {base} (got {r.status})")
    r = via_proxy(proxy, "GET", base + "/prefs", headers={"Cookie": COOKIE})
    check(r.status == 200, f"GET /prefs through the proxy -> 200 on {base} (got {r.status})")


def reflections(xss: list[dict]) -> tuple[list[dict], list[dict]]:
    hdr = [i for i in xss if (i.get("location") or {}).get("kind") == "header"
           and (i.get("location") or {}).get("path") == "/whoami"]
    ck = [i for i in xss if (i.get("location") or {}).get("kind") == "cookie"
          and (i.get("location") or {}).get("path") == "/prefs"]
    return hdr, ck


def main() -> None:
    work = tempfile.mkdtemp(prefix="aitm-e2e-t2-mutable-")
    try:
        with ScanTarget("vulnerable") as V, ScanTarget("patched") as P:
            cfg = CoreConfig(proxy_port=free_port(), scope_entries=[V.authority, P.authority],
                             findings_dir=os.path.join(work, "findings"))
            with Aitm.server(cfg) as core:
                op = BusClient.operator(core)
                require_verbs(op, "scan.start", "scan.status", "scan.issues")
                require_lane(op, "http")
                proxy = cfg.proxy_port

                section("real proxied captures of /whoami and /prefs on V and P")
                capture(proxy, V.base)
                capture(proxy, P.base)
                check("<p>agent: " + UA in via_proxy(proxy, "GET", V.base + "/whoami",
                                                     headers={"User-Agent": UA}).text,
                      "V reflects the User-Agent raw (the seed is live)")

                section("V: header and cookie reflections are found")
                seq_v = V.logs.reset()
                job_v = start_job(op, "operator", target=V.base)["job"]
                st = wait_terminal(op, "operator", job_v, timeout=900)
                check(st.get("state") == "done", f"V job ended done (state={st.get('state')!r}, "
                                                 f"stopped_reason={st.get('stopped_reason')!r})")
                xss_v = issues(op, "operator", job=job_v, **{"class": "xss"})
                hdr_v, ck_v = reflections(xss_v)
                ok(f"V: {len(xss_v)} xss issues; locations = "
                   f"{sorted((i['location'].get('kind'), i['location'].get('path'), i['location'].get('name')) for i in xss_v)}")
                check(bool(hdr_v), "V: an xss issue with location.kind == header on /whoami")
                check({str(i["location"].get("name")).lower() for i in hdr_v} & {"user-agent", "x-forwarded-for"} != set(),
                      f"V: the header issue names User-Agent or X-Forwarded-For ({[i['location'].get('name') for i in hdr_v]})")
                check(bool(ck_v), "V: an xss issue with location.kind == cookie on /prefs")
                check(all(i["location"].get("name") == "theme" for i in ck_v),
                      f"V: the cookie issue names theme ({[i['location'].get('name') for i in ck_v]})")
                check(all(i.get("lane") == "http" for i in hdr_v + ck_v), "V: both issues are on the http lane")

                section("observer: the mutations reached V")
                reqs_v = V.logs.scanner_requests(seq_v)
                whoami = [e for e in reqs_v if e.get("path") == "/whoami"]
                mutated_hdr = [e for e in whoami
                               if (e.get("headers") or {}).get("x-forwarded-for") not in (None, XFF)
                               or (e.get("headers") or {}).get("user-agent") not in (None, UA)]
                check(bool(whoami), f"V log shows scanner requests to /whoami ({len(whoami)})")
                check(bool(mutated_hdr),
                      f"V log shows /whoami requests with a mutated user-agent or x-forwarded-for ({len(mutated_hdr)})")
                prefs = [e for e in reqs_v if e.get("path") == "/prefs"]
                mutated_ck = [e for e in prefs
                              if e.get("cookie_names") == ["theme"] and e.get("cookie_sha256") not in (None, COOKIE_SHA16)]
                check(bool(prefs), f"V log shows scanner requests to /prefs ({len(prefs)})")
                check(bool(mutated_ck),
                      f"V log shows /prefs requests carrying a theme cookie other than the captured one ({len(mutated_ck)})")
                check(all("cookie" not in e for e in reqs_v), "the target log stores no raw cookie key")

                section("P: neither reflection is reported")
                seq_p = P.logs.reset()
                job_p = start_job(op, "operator", target=P.base)["job"]
                st = wait_terminal(op, "operator", job_p, timeout=900)
                check(st.get("state") == "done", f"P job ended done (state={st.get('state')!r}, "
                                                 f"stopped_reason={st.get('stopped_reason')!r})")
                xss_p = issues(op, "operator", job=job_p, **{"class": "xss"})
                hdr_p, ck_p = reflections(xss_p)
                check(not hdr_p, f"P: no header xss issue on /whoami ({len(hdr_p)})")
                check(not ck_p, f"P: no cookie xss issue on /prefs ({len(ck_p)})")
                reqs_p = P.logs.scanner_requests(seq_p)
                check(any(e.get("path") == "/whoami" for e in reqs_p) and any(e.get("path") == "/prefs" for e in reqs_p),
                      f"P log shows the scanner probed /whoami and /prefs too ({len(reqs_p)} requests)")
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
