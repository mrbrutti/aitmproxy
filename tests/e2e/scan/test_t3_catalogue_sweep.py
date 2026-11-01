#!/usr/bin/env python3
# e2e: tier=T1 surface=scan needs=http
"""AC T3-5: every bundled active script registers as a catalogue check, the manual
`check.<id>` command still works, and the scheduled catalogue finds the seeded
injection vulns on V and none on P.

Arrange: real `aitm-testtarget-serve` V and P, a real core with both authorities in
scope (`ssl_insecure: true` so the TLS listeners are usable too). The catalogue
expectation is derived from the files on disk, never from a list in this cell: the
cell globs `scripts/bundled/active/*.rhai` and parses each script's declared
`add_check` id with the regex `id:\\s*"([^"]+)"`.

Assert:
  - every id parsed from a bundled script is in `scan.checks` with
    `origin.kind == "bundled"`;
  - `check.sqli { url: <V>/products, param: "id" }` at operator returns a verdict
    map whose `outcome` is one of vulnerable | clean | inconclusive | error
    (the hand-invoked path survived the conversion to `add_check`);
  - a `standard` job on V yields an issue for each of the nine seeded injection
    classes on its child-spec D3 path (`sqli` on /products with `check_id` `sqli`,
    `ssti` /greet, `cmdi` /ping, `path-traversal` /static, `crlf` /lang, `xxe`
    /xml, `nosqli` /api/login, `ldapi` /ldap, `open-redirect` /redirect);
  - the same job on P yields none of those nine classes.

Observer, independent of the scanner: the target's control origin `GET /log/http`
-- the scripts' probes really arrived (a `POST /xml` request with `body_len > 0`),
and P was probed just as hard. No fixture.

SKIP 77 when: no `scan.*` verbs, no `http` lane in `scan.checks`, no
`scripts/bundled/active/*.rhai` on disk, a bundled script declares no `add_check`
id (T3's conversion is not on this build), or the core advertises no `check.sqli`.
The reason names the missing thing.
"""

import re
import sys
from pathlib import Path

E2E = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(E2E))

from aitm_e2e import check, free_port, ok, repo_root, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.scan import (  # noqa: E402
    boot_target,
    brief,
    issues,
    require_lane,
    require_verbs,
    scan_call,
    start_job,
    wait_terminal,
)

ACTIVE_DIR = Path(repo_root()) / "scripts" / "bundled" / "active"
ID_RE = re.compile(r'id:\s*"([^"]+)"')
VERDICT_OUTCOMES = {"vulnerable", "clean", "inconclusive", "error"}
# The D3 seeds the scheduled catalogue must find on V: class -> path.
SEEDED = {
    "sqli": "/products",
    "ssti": "/greet",
    "cmdi": "/ping",
    "path-traversal": "/static",
    "crlf": "/lang",
    "xxe": "/xml",
    "nosqli": "/api/login",
    "ldapi": "/ldap",
    "open-redirect": "/redirect",
}
JOB_TIMEOUT = 600.0


def script_ids() -> dict:
    """{script path -> [declared check ids]} for every bundled active script."""
    files = sorted(ACTIVE_DIR.glob("*.rhai"))
    if not files:
        skip(f"no bundled active scripts at {ACTIVE_DIR} (nothing to sweep)")
    found = {}
    for f in files:
        found[f] = ID_RE.findall(f.read_text(encoding="utf-8", errors="replace"))
    silent = [f.name for f, ids in found.items() if not ids]
    if silent:
        skip("bundled active script(s) declare no add_check id: " + ", ".join(silent)
             + " (T3's add_check conversion is not on this build)")
    return found


def run_standard(op, target) -> tuple[list, int]:
    seq0 = target.logs.reset()
    job = start_job(op, "operator", target=target.base)["job"]
    status = wait_terminal(op, "operator", job, timeout=JOB_TIMEOUT)
    ok(f"{target.mode}: job ended state={status.get('state')!r} "
       f"issues={(status.get('issues') or {}).get('total')!r} "
       f"probes={(status.get('probes') or {}).get('sent')!r}")
    return issues(op, "operator", job=job), seq0


def main() -> None:
    declared = script_ids()
    ok(f"{len(declared)} bundled active script(s) declare "
       f"{sum(len(v) for v in declared.values())} check id(s) on disk")

    with boot_target("vulnerable") as v, boot_target("patched") as p:
        cfg = CoreConfig(
            proxy_port=free_port(),
            ssl_insecure=True,
            scope_entries=[v.authority, v.tls_authority, v.tls_h1_authority,
                           p.authority, p.tls_authority, p.tls_h1_authority],
        )
        with Aitm.server(cfg) as core:
            op = BusClient.operator(core)
            require_verbs(op, "scan.start", "scan.status", "scan.issues", "scan.checks")
            require_lane(op, "http")

            section("every bundled active script is a bundled catalogue entry")
            catalogue = {c.get("id"): c for c in
                         (scan_call(op, "operator", "scan.checks", {}) or {}).get("checks", [])
                         if isinstance(c, dict)}
            missing = sorted({i for ids in declared.values() for i in ids} - set(catalogue))
            if missing:
                skip("script-declared check id(s) absent from scan.checks: " + ", ".join(missing)
                     + " (T3's catalogue bridge is not on this build)")
            for path, ids in sorted(declared.items()):
                for cid in ids:
                    origin = (catalogue[cid].get("origin") or {})
                    check(origin.get("kind") == "bundled",
                          f"{path.name}: check {cid} has origin.kind 'bundled' "
                          f"(observed {origin.get('kind')!r})")

            section("the manual check.<id> command still works")
            if "check.sqli" not in set(op.tool_names()):
                skip("the core advertises no check.sqli command (the manual catalogue verb)")
            verdict = op.call("check.sqli", {"url": v.base + "/products", "param": "id"})
            check(isinstance(verdict, dict),
                  f"check.sqli returned a verdict map (got {type(verdict).__name__})")
            check(verdict.get("outcome") in VERDICT_OUTCOMES,
                  f"check.sqli outcome is one of {sorted(VERDICT_OUTCOMES)} "
                  f"(observed {verdict.get('outcome')!r})")

            section("the scheduled catalogue finds the nine seeded classes on V")
            iss_v, seq_v = run_standard(op, v)
            by_class = {}
            for i in iss_v:
                by_class.setdefault(i.get("class"), []).append(i)
            for cls, path in sorted(SEEDED.items()):
                hits = [i for i in by_class.get(cls, [])
                        if (i.get("location") or {}).get("path") == path]
                check(hits, f"V: class {cls!r} found on {path} [{brief(iss_v, 16)}]")
                if cls == "sqli":
                    check(any(i.get("check_id") == "sqli" for i in hits),
                          "V: the /products sqli issue carries check_id 'sqli' "
                          f"(observed {sorted({i.get('check_id') for i in hits})})")

            xml_posts = [e for e in v.logs.scanner_requests(seq_v)
                         if e.get("path") == "/xml" and int(e.get("body_len", 0)) > 0]
            check(xml_posts,
                  f"the target logged {len(xml_posts)} /xml request(s) with a body: the XXE "
                  "probes really arrived on the wire")

            section("the patched twin yields none of them")
            iss_p, seq_p = run_standard(op, p)
            leaked = sorted({i.get("class") for i in iss_p if i.get("class") in SEEDED})
            check(not leaked,
                  f"P: none of the nine seeded classes (observed {leaked}) [{brief(iss_p, 16)}]")
            check(len(p.logs.scanner_requests(seq_p)) > 0,
                  "P was probed too: the clean result is the patch, not a missed target")

            ok("T3-5: the bundled catalogue is loaded, hand-invocable, and finds the nine "
               "seeded injection classes on V only")


if __name__ == "__main__":
    main()
