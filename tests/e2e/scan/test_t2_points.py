#!/usr/bin/env python3
# e2e: tier=T1 surface=scan needs=http
"""scan/t2_points -- AC T2-2: after real proxied captures of the seeded point
routes (`POST /api/profile` JSON, `POST /xml`, `POST /upload` multipart, `GET /prefs`
with a `theme` cookie, `GET /whoami` with `X-Forwarded-For`, `GET /docs/intro`,
`GET /files/readme.txt`), a `scan.map` (client crawler) site map's insertion points
cover the kinds `json_value` (nested path `profile.address.city`), `xml_value`,
`multipart_value`, `header`, `cookie`, `path_segment` (non-numeric, on `/docs/intro`)
and `path_filename`; the `theme` cookie point's `example` is `<redacted>`.

Observers: the target's control log (`/log/http`) shows the cell's proxied captures
arriving with `cookie_names == ["theme"]` on `/prefs` and the `x-forwarded-for`
header on `/whoami` (the captures the site map is built from really happened).

SKIP 77: serve binary missing, a missing `scan.map`/`scan.status`/`scan.sitemap`
verb, or no `http` lane in `scan.checks` (the T2 lane is not on this build).
"""
import os
import shutil
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, free_port, ok, section  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.proxyutil import via_proxy  # noqa: E402
from aitm_e2e.scan import (  # noqa: E402
    boot_target,
    map_job,
    require_crate_lane,
    require_lane,
    require_verbs,
    sitemap,
    wait_terminal,
)

# The browser crawl drives a real obscura engine, so a T2 job runs far longer
# than the 600 s the engine-only cells need.
JOB_TIMEOUT = 900.0

WANTED_KINDS = {"json_value", "xml_value", "multipart_value", "header", "cookie",
                "path_segment", "path_filename"}
BOUNDARY = "aitm-e2e-boundary-7f3a"
MULTIPART = (
    f"--{BOUNDARY}\r\n"
    'Content-Disposition: form-data; name="file"; filename="notes.txt"\r\n'
    "Content-Type: text/plain\r\n\r\n"
    "abc\r\n"
    f"--{BOUNDARY}\r\n"
    'Content-Disposition: form-data; name="note"\r\n\r\n'
    "hello\r\n"
    f"--{BOUNDARY}--\r\n"
).encode("utf-8")


def url_path(point: dict) -> str | None:
    url = point.get("url")
    return urlsplit(url).path if isinstance(url, str) else None


def main() -> None:
    work = tempfile.mkdtemp(prefix="aitm-e2e-t2-points-")
    try:
        with boot_target("vulnerable") as V:
            cfg = CoreConfig(proxy_port=free_port(), scope_entries=[V.authority],
                             findings_dir=os.path.join(work, "findings"))
            with Aitm.server(cfg) as core:
                op = BusClient.operator(core)
                require_verbs(op, "scan.map", "scan.status", "scan.sitemap")
                require_lane(op, "http")
                require_crate_lane(op, "http", "needs T2 (aitm-scan-http)")
                proxy = cfg.proxy_port

                section("real proxied captures of the seeded point routes")
                seq0 = V.logs.reset()
                captures = [
                    ("POST", "/api/profile", {"Content-Type": "application/json"},
                     b'{"profile":{"address":{"city":"Lisbon"}}}'),
                    ("POST", "/xml", {"Content-Type": "text/xml"},
                     b'<order id="7"><name>pen</name></order>'),
                    ("POST", "/upload", {"Content-Type": f"multipart/form-data; boundary={BOUNDARY}"},
                     MULTIPART),
                    ("GET", "/prefs", {"Cookie": "theme=dark"}, None),
                    ("GET", "/whoami", {"X-Forwarded-For": "1.2.3.4"}, None),
                    ("GET", "/docs/intro", {}, None),
                    ("GET", "/files/readme.txt", {}, None),
                ]
                for method, path, headers, body in captures:
                    r = via_proxy(proxy, method, V.base + path, headers=headers, body=body)
                    check(r.status == 200, f"{method} {path} through the proxy -> 200 (got {r.status})")
                check("Lisbon" in via_proxy(proxy, "POST", V.base + "/api/profile",
                                            headers={"Content-Type": "application/json"},
                                            body=b'{"profile":{"address":{"city":"Lisbon"}}}').text,
                      "the nested JSON city is reflected by V (the capture is a real seed hit)")

                section("observer: the target logged the captures with the right shape")
                logged = V.logs.scanner_requests(seq0)
                prefs = [e for e in logged if e.get("path") == "/prefs"]
                check(bool(prefs) and prefs[0].get("cookie_names") == ["theme"],
                      f"/prefs capture logged with cookie_names == ['theme'] "
                      f"({[e.get('cookie_names') for e in prefs]})")
                check(all("cookie" not in e for e in logged), "the target log stores no raw cookie key")
                whoami = [e for e in logged if e.get("path") == "/whoami"]
                xff = [(e.get("headers") or {}).get("x-forwarded-for") for e in whoami]
                check("1.2.3.4" in xff, f"/whoami capture logged with x-forwarded-for ({xff})")
                paths_logged = {e.get("path") for e in logged}
                check({"/api/profile", "/xml", "/upload", "/docs/intro", "/files/readme.txt"} <= paths_logged,
                      f"every capture reached the target ({sorted(paths_logged)})")

                section("scan.map (client crawler) builds points from the captures")
                res = map_job(op, "operator", target=V.base,
                              overrides={"crawl": {"use_browser": "never"}})
                job = res["job"]
                st = wait_terminal(op, "operator", job, timeout=JOB_TIMEOUT)
                check(st.get("state") == "done", f"scan.map job ended done (state={st.get('state')!r})")
                _nodes, points = sitemap(op, "operator", job)
                kinds = {p.get("kind") for p in points}
                ok(f"{len(points)} points; kinds = {sorted(k for k in kinds if isinstance(k, str))}")
                check(WANTED_KINDS <= kinds, f"kinds cover {sorted(WANTED_KINDS)} (missing: {sorted(WANTED_KINDS - kinds)})")

                section("the individual points")
                json_pts = [p for p in points if p.get("kind") == "json_value"]
                check(any(p.get("path") == "profile.address.city" for p in json_pts),
                      f"a json_value point has path profile.address.city ({[p.get('path') for p in json_pts]})")
                city = [p for p in json_pts if p.get("path") == "profile.address.city"]
                check(bool(city) and url_path(city[0]) == "/api/profile",
                      f"the nested json_value point is on /api/profile ({[url_path(p) for p in city]})")
                theme = [p for p in points if p.get("kind") == "cookie" and p.get("name") == "theme"]
                check(bool(theme), "a cookie point named theme exists")
                check(all(p.get("example") == "<redacted>" for p in theme),
                      f"cookie theme example is <redacted> ({[p.get('example') for p in theme]})")
                check(all("dark" not in str(p.get("example")) for p in points),
                      "no point example carries the raw cookie value")
                seg = [p for p in points if p.get("kind") == "path_segment"]
                check(any(url_path(p) == "/docs/intro" or p.get("example") == "intro" for p in seg),
                      f"a path_segment point is on /docs/intro ({[(url_path(p), p.get('example')) for p in seg]})")
                check(not any(url_path(p) in ("/account/1", "/account/2") for p in seg),
                      "no path_segment point on the numeric /account/{id} segments")
                fname = [p for p in points if p.get("kind") == "path_filename"]
                check(any(url_path(p) == "/files/readme.txt" or (p.get("example") or "").startswith("readme")
                          for p in fname),
                      f"a path_filename point is on /files/readme.txt ({[(url_path(p), p.get('example')) for p in fname]})")
                hdr = [p for p in points if p.get("kind") == "header"]
                hdr_names = {str(p.get("name")).lower() for p in hdr}
                check("x-forwarded-for" in hdr_names, f"a header point named x-forwarded-for exists ({sorted(hdr_names)})")
                mp = [p for p in points if p.get("kind") == "multipart_value"]
                check(any(p.get("name") == "note" for p in mp),
                      f"a multipart_value point named note exists ({[p.get('name') for p in mp]})")
                check(all(p.get("lane") == "http" for p in points), "every point is on the http lane")
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
