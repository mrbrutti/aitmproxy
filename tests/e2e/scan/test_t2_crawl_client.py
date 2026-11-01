#!/usr/bin/env python3
# e2e: tier=T1 surface=scan needs=http
"""scan/t2_crawl_client -- AC T2-1 (client half): `scan.map` with
`crawl.use_browser: never` drives the no-JS client crawler, which reaches every
anchor and form route the target's own index page links (the click-only
`/files/readme.txt` is NOT required: it needs a browser) and templates
`/account/1` + `/account/2` as `path_template` `/account/{id}`; `GET /search` is a
node with a `q` query param.

Observers: the index page the target itself serves (parsed here: ground truth for
what is linked) and the target's control log (`/log/http`), which shows a `GET` for
every anchor path and a request at every form action.

SKIP 77: serve binary missing, a missing `scan.map`/`scan.status`/`scan.sitemap`
verb, or no `http` lane in `scan.checks` (the T2 lane is not on this build).
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

from aitm_e2e import check, free_port, ok, section  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.scan import (  # noqa: E402
    ScanTarget,
    map_job,
    require_lane,
    require_verbs,
    scan_call,
    wait_terminal,
)


def fetch_index(base: str) -> str:
    """GET `<base>/` straight from the target (no proxy, ignoring any proxy env)."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(base + "/", timeout=10) as resp:  # noqa: S310  (loopback only)
        return resp.read().decode("utf-8", errors="replace")


def linked_paths(html: str, pattern: str) -> set[str]:
    """The paths (query stripped) of every `pattern` capture that is a local path."""
    out = set()
    for raw in re.findall(pattern, html):
        if raw.startswith("/") and raw != "/":
            out.add(urlsplit(raw).path)
    return out


def templated(path: str) -> str:
    """The D8.1 collapse a crawler applies: numeric segments become `{id}`."""
    return re.sub(r"/\d+(?=/|$)", "/{id}", path)


def sitemap_nodes(op, job: str) -> list[dict]:
    nodes: dict[str, dict] = {}
    cursor = None
    seen: set[str] = set()
    while True:
        args: dict = {"job": job, "limit": 1024}
        if cursor:
            args["cursor"] = cursor
        page = scan_call(op, "operator", "scan.sitemap", args)
        for n in page.get("nodes") or []:
            nodes[n.get("id") or f"{n.get('method')} {n.get('path_template')}"] = n
        cursor = page.get("next_cursor")
        if not cursor or cursor in seen:
            return list(nodes.values())
        seen.add(cursor)


def main() -> None:
    work = tempfile.mkdtemp(prefix="aitm-e2e-t2-crawl-client-")
    try:
        with ScanTarget("vulnerable") as V:
            cfg = CoreConfig(proxy_port=free_port(), scope_entries=[V.authority],
                             findings_dir=os.path.join(work, "findings"))
            with Aitm.server(cfg) as core:
                op = BusClient.operator(core)
                require_verbs(op, "scan.map", "scan.status", "scan.sitemap")
                require_lane(op, "http")

                section("ground truth: anchors and forms on the target's own index")
                html = fetch_index(V.base)
                anchors = linked_paths(html, r'href="([^"]+)"')
                forms = linked_paths(html, r'action="([^"]+)"')
                check(len(anchors) >= 20, f"index anchors parsed ({len(anchors)})")
                check(forms == {"/search", "/comments", "/login", "/upload"},
                      f"index forms parsed: {sorted(forms)}")
                expected = anchors | forms

                section("scan.map with crawl.use_browser: never")
                seq0 = V.logs.reset()
                res = map_job(op, "operator", target=V.base,
                              overrides={"crawl": {"use_browser": "never"}})
                job = res["job"]
                ok(f"job {job} started (lanes run={res.get('lanes', {}).get('run')})")
                st = wait_terminal(op, "operator", job, timeout=900)
                check(st.get("state") == "done", f"scan.map job ended done (state={st.get('state')!r})")
                ok(f"crawl counters: {st.get('crawl')}")

                section("site map covers every anchor and form route")
                nodes = sitemap_nodes(op, job)
                templates = {n.get("path_template") for n in nodes}
                missing = sorted(p for p in expected
                                 if p not in templates and templated(p) not in templates)
                check(not missing, f"every anchor/form path is a site-map node (missing: {missing})")
                check("/account/{id}" in templates, "path_template /account/{id} present")
                ok(f"click-only /files/readme.txt {'is' if '/files/readme.txt' in templates else 'is not'} "
                   "a node (not required without a browser)")
                search = [n for n in nodes
                          if n.get("method") == "GET" and n.get("path_template") == "/search"]
                check(bool(search), "GET /search node present")
                params = {(p.get("kind"), p.get("name")) for n in search for p in (n.get("params") or [])}
                check(("query", "q") in params, f"GET /search node carries query param q ({sorted(params)})")

                section("observer: the target saw the client crawler at every anchor and form")
                reqs = V.logs.scanner_requests(seq0)
                gets = {e.get("path") for e in reqs if e.get("method") == "GET"}
                not_got = sorted(anchors - gets)
                check(not not_got, f"target log shows a GET at every anchor path (unvisited: {not_got})")
                by_path: dict[str, set[str]] = {}
                for e in reqs:
                    by_path.setdefault(e.get("path"), set()).add(e.get("method"))
                not_reached = sorted(p for p in forms if p not in by_path)
                check(not not_reached, f"target log shows a request at every form action (unreached: {not_reached})")
                ok("form actions reached with methods: "
                   + ", ".join(f"{p} {sorted(by_path.get(p, set()))}" for p in sorted(forms)))
                ok(f"{len(reqs)} crawler requests logged by the target")
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
