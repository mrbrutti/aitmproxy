#!/usr/bin/env python3
# e2e: tier=T1 surface=scan needs=obscura
"""scan/t2_crawl -- AC T2-1 (browser half): `scan.map` against V with REAL obscura
reaches every route the target's own index page links: anchor hrefs, form actions
(a form submission), the click-only `data-href` span (`/files/readme.txt`) and the
inline-script `fetch(...)` POSTs; the site map templates `/account/1` + `/account/2`
as `path_template` `/account/{id}` and has a `GET /search` node with a `q` query param.

Observers: the index page the target itself serves (parsed by this cell: ground truth
for what is linked) and the target's control log (`/log/http`), which shows the
crawler's requests actually arriving at each linked path.

SKIP 77: `AITM_OBSCURA != "1"` (browser crawl needs the real engine), the serve
binary missing, a missing `scan.map`/`scan.status`/`scan.sitemap` verb, or no
`http` lane in `scan.checks` (the T2 lane is not on this build).
"""
import os
import re
import shutil
import sys
import tempfile
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, free_port, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.scan import (  # noqa: E402
    boot_target,
    map_job,
    require_lane,
    require_verbs,
    sitemap,
    wait_terminal,
)

# The browser crawl drives a real obscura engine, so a T2 job runs far longer
# than the 600 s the engine-only cells need.
JOB_TIMEOUT = 900.0


def fetch_index(base: str) -> str:
    """GET `<base>/` straight from the target (no proxy, ignoring any proxy env)."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(base + "/", timeout=10) as resp:  # noqa: S310  (loopback only)
        return resp.read().decode("utf-8", errors="replace")


def linked_paths(html: str) -> dict[str, set[str]]:
    """The paths (query stripped) the index discloses, by discovery kind."""
    def paths(pattern: str) -> set[str]:
        out = set()
        for raw in re.findall(pattern, html):
            if raw.startswith("/") and raw != "/":
                out.add(urlsplit(raw).path)
        return out

    return {
        "href": paths(r'href="([^"]+)"'),
        "action": paths(r'action="([^"]+)"'),
        "data-href": paths(r'data-href="([^"]+)"'),
        "fetch": paths(r'fetch\("([^"]+)"'),
    }


def templated(path: str) -> str:
    """The D8.1 collapse a crawler applies: numeric segments become `{id}`."""
    return re.sub(r"/\d+(?=/|$)", "/{id}", path)


def main() -> None:
    if os.environ.get("AITM_OBSCURA") != "1":
        skip("AITM_OBSCURA != 1: the browser crawl needs the real obscura engine")

    work = tempfile.mkdtemp(prefix="aitm-e2e-t2-crawl-")
    try:
        with boot_target("vulnerable") as V:
            cfg = CoreConfig(proxy_port=free_port(), scope_entries=[V.authority],
                             findings_dir=os.path.join(work, "findings"))
            with Aitm.server(cfg) as core:
                op = BusClient.operator(core)
                require_verbs(op, "scan.map", "scan.status", "scan.sitemap")
                require_lane(op, "http")

                section("ground truth: what the target's own index links")
                groups = linked_paths(fetch_index(V.base))
                expected = set().union(*groups.values())
                check(len(groups["href"]) >= 20, f"index anchors parsed ({len(groups['href'])})")
                check(groups["action"] == {"/search", "/comments", "/login", "/upload"},
                      f"index forms parsed: {sorted(groups['action'])}")
                check(groups["data-href"] == {"/files/readme.txt"},
                      f"click-only span parsed: {sorted(groups['data-href'])}")
                check(groups["fetch"] == {"/api/profile", "/api/login", "/xml"},
                      f"inline-script fetch paths parsed: {sorted(groups['fetch'])}")
                ok(f"{len(expected)} distinct linked paths expected")

                section("scan.map with the real browser")
                seq0 = V.logs.reset()
                # This cell IS the browser-crawl proof: opt out of the harness's
                # client-crawl default (use_browser: never) explicitly.
                res = map_job(op, "operator", target=V.base,
                              overrides={"crawl": {"use_browser": "auto"}})
                job = res["job"]
                ok(f"job {job} started (lanes run={res.get('lanes', {}).get('run')})")
                st = wait_terminal(op, "operator", job, timeout=JOB_TIMEOUT)
                check(st.get("state") == "done", f"scan.map job ended done (state={st.get('state')!r})")
                crawl = st.get("crawl") or {}
                ok(f"crawl counters: pages={crawl.get('pages')} forms_submitted={crawl.get('forms_submitted')}")
                check((crawl.get("forms_submitted") or 0) >= 1, "at least one form was submitted")

                section("site map covers every linked path")
                nodes, _points = sitemap(op, "operator", job)
                templates = {n.get("path_template") for n in nodes}
                missing = sorted(p for p in expected
                                 if p not in templates and templated(p) not in templates)
                check(not missing, f"every linked path is a site-map node (missing: {missing})")
                check("/account/{id}" in templates, "path_template /account/{id} present")
                check("/files/readme.txt" in templates, "click-only /files/readme.txt is a node")
                search = [n for n in nodes
                          if n.get("method") == "GET" and n.get("path_template") == "/search"]
                check(bool(search), "GET /search node present")
                params = {(p.get("kind"), p.get("name")) for n in search for p in (n.get("params") or [])}
                check(("query", "q") in params, f"GET /search node carries query param q ({sorted(params)})")

                section("observer: the target saw the crawler at every linked path")
                reqs = V.logs.scanner_requests(seq0)
                hit_paths = {e.get("path") for e in reqs}
                not_hit = sorted(expected - hit_paths)
                check(not not_hit, f"target log shows a request at every linked path (unvisited: {not_hit})")
                methods_files = {e.get("method") for e in reqs if e.get("path") == "/files/readme.txt"}
                check("GET" in methods_files, "target log shows GET /files/readme.txt (the click-only link)")
                form_posts = {e.get("path") for e in reqs if e.get("method") == "POST"}
                check(bool(form_posts & {"/comments", "/login", "/upload"}),
                      f"target log shows a form POST ({sorted(form_posts)})")
                ok(f"{len(reqs)} crawler requests logged by the target")
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
