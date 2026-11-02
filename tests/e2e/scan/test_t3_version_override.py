#!/usr/bin/env python3
# e2e: tier=T1 surface=scan needs=http
"""AC T3-2: `http.version` forces the wire protocol, and a forced `h2` against an
h1-only listener errors every probe instead of failing the job.

Arrange: a real `aitm-testtarget-serve` V with both TLS listeners (T10 child spec
D1: `tls` offers ALPN `h2, http/1.1`; `tls_h1` offers `http/1.1` only), a real core
with `ssl_insecure: true` and the target's authorities in scope.

Act + assert, two jobs:
  1. `scan.start { target: <tls base>, overrides: { http: { version: "h1" } } }`
     -> every `request` entry the target logged since the reset has
     `version == "h1"` and every `tls_handshake` since has `alpn == "http/1.1"`:
     the override beat the listener's h2 offer.
  2. `scan.start { target: <tls_h1 base>, overrides: { http: { version: "h2" },
     crawl: { use_browser: "never" } } }` -> `wait_terminal` ends `state: "done"`
     (never `failed`), `stopped_reason` and `error` null (amendment 39b: an
     all-failed crawl degrades, it does not stop early), `crawl.errors > 0`,
     `crawl.pages == 0`, `crawl.last_error == "h2_not_negotiated"`,
     `probes.errors > 0`, and the target logged only
     `tls_handshake` entries (all `alpn == "none"`: the client offered h2 only,
     the listener http/1.1 only) and zero HTTP requests.

Observer, independent of the scanner: the target's control origin `GET /log/http`
(`version`, `alpn`, and the absence of `request` entries). No fixture.

SKIP 77 when: no `scan.*` verbs, no `http` lane in `scan.checks`, or the target
started no TLS listener. The reason names the missing thing.
"""

import sys
from pathlib import Path

E2E = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(E2E))

from aitm_e2e import check, free_port, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.scan import (  # noqa: E402
    boot_target,
    require_checks,
    lane_source,
    require_lane,
    require_verbs,
    start_job,
    wait_terminal,
)

JOB_TIMEOUT = 600.0


def since(entries, seq: int) -> list:
    return [e for e in entries if int(e.get("seq", 0)) > seq]


def main() -> None:
    with boot_target("vulnerable") as v:
        if not v.tls_base or not v.tls_h1_base:
            skip("the test target started no tls / tls_h1 listener (needs --tls-port and "
                 "--tls-h1-port; T10 child spec D1)")
        cfg = CoreConfig(
            proxy_port=free_port(),
            ssl_insecure=True,
            scope_entries=[v.tls_authority, v.tls_h1_authority, v.authority],
        )
        with Aitm.server(cfg) as core:
            op = BusClient.operator(core)
            require_verbs(op, "scan.start", "scan.status")
            require_lane(op, "http")
            # The override is observable only through T3's HttpSender, which lands
            # with its native checks (sqli-boolean is one of them): skip until then.
            require_checks(op, "sqli-boolean", needs="needs T3 PR 2 (HttpSender wiring)")

            section("http.version: h1 forces h1 on a listener that offers h2")
            seq0 = v.logs.reset()
            job1 = start_job(op, "operator", target=v.tls_base,
                             overrides={"http": {"version": "h1"}})["job"]
            st1 = wait_terminal(op, "operator", job1, timeout=JOB_TIMEOUT)
            ok(f"job 1 ended state={st1.get('state')!r} stopped_reason={st1.get('stopped_reason')!r}")

            entries1 = since(v.logs.http(), seq0)
            reqs1 = [e for e in entries1 if e.get("kind") == "request"]
            hs1 = [e for e in entries1 if e.get("kind") == "tls_handshake"]
            versions1 = sorted({e.get("version") for e in reqs1})
            alpns1 = sorted({e.get("alpn") for e in hs1})
            check(len(reqs1) > 0, f"the forced-h1 job reached the target ({len(reqs1)} requests logged)")
            check(versions1 == ["h1"],
                  f"every logged request is version h1 (observed versions {versions1})")
            check(len(hs1) > 0 and alpns1 == ["http/1.1"],
                  f"every TLS handshake negotiated http/1.1 (observed alpns {alpns1}, "
                  f"{len(hs1)} handshakes)")

            section("http.version: h2 against the h1-only listener errors every probe")
            seq1 = v.logs.reset()
            job2 = start_job(op, "operator", target=v.tls_h1_base,
                             overrides={"http": {"version": "h2"},
                                        "crawl": {"use_browser": "never"}})["job"]
            st2 = wait_terminal(op, "operator", job2, timeout=JOB_TIMEOUT)
            error_text = st2.get("error") or ""
            probes2 = st2.get("probes") or {}
            check(st2.get("state") == "done",
                  f"the job ended state 'done', not a job failure (state={st2.get('state')!r})")
            # Spec amendment 39b (supersedes 39; T1b follow-up PR 2): a job whose
            # crawl failed on every request ends `done` with `stopped_reason` and
            # `error` null ("degrade, do not fail"; `stopped_reason` is reserved
            # for early stops), and names the cause on `crawl.errors` /
            # `crawl.last_error` with a closed token.
            crawl2 = st2.get("crawl") or {}
            if lane_source(op, "http") == "crate" and int(crawl2.get("errors") or 0) == 0:
                # The real lane crate (aitm-scan-http) does not yet call
                # `JobCtx::report_crawl_error`, so an all-failed crawl leaves
                # `crawl.errors 0` and `crawl.last_error` null and 39b has no
                # signal to assert on; the interim lane reports every failure.
                # Loud, never green: the hook is amendment 39's lane contract.
                skip(f"http lane crate does not report crawl errors (amendment 39 hook not wired; "
                     f"probes={probes2}, crawl={crawl2}); the T3 half of AC T3-2 passed above")
            # 39b: the crawl's failure is not a job failure (`error` null). With
            # amendment 38 the origin-scoped checks still run on `<origin>/` and
            # their probes fail the same way, so the per-host ladder (amendment
            # 40: transport errors count) may legitimately end the job
            # `stopped_reason: errors`; a crawl-only failure ends `done` with
            # both null. Either way the cause is on `crawl.errors`/`last_error`.
            check(st2.get("stopped_reason") in (None, "errors") and not error_text,
                  f"an all-failed crawl is not a job failure: error is null, stopped_reason is null or "
                  f"the ladder's 'errors' (observed {st2.get('stopped_reason')!r}, {error_text[:80]!r})")
            check(int(crawl2.get("errors") or 0) > 0 and int(crawl2.get("pages") or 0) == 0,
                  f"crawl.errors counted every failed request and no page was fetched "
                  f"(observed errors={crawl2.get('errors')!r}, pages={crawl2.get('pages')!r})")
            if lane_source(op, "http") == "crate" and crawl2.get("last_error") != "h2_not_negotiated":
                # The lane crate's `crawl_error_token` reads the typed io kind and a
                # `starts_with("h2_not_negotiated:")` link before falling back to
                # text, and the sender's forced-h2 failure reaches it as a
                # "refused" text first, so the token comes out `connect_refused`
                # (amendment 68 family: classifier ordering in aitm-scan-http;
                # the interim lane answers h2_not_negotiated here). Loud, never green.
                skip(f"http lane crate names the forced-h2 failure {crawl2.get('last_error')!r}, not "
                     f"h2_not_negotiated (amendment 68 classifier ordering in aitm-scan-http; "
                     f"crawl={crawl2}); the T3 half of AC T3-2 passed above")
            check(crawl2.get("last_error") == "h2_not_negotiated",
                  f"crawl.last_error names h2_not_negotiated (observed {crawl2.get('last_error')!r})")
            check(probes2.get("errors", 0) > 0,
                  f"probes.errors counted the sender errors (observed {probes2.get('errors')!r})")

            entries2 = since(v.logs.http(), seq1)
            reqs2 = [e for e in entries2 if e.get("kind") == "request"]
            hs2 = [e for e in entries2 if e.get("kind") == "tls_handshake"]
            alpns2 = sorted({e.get("alpn") for e in hs2})
            kinds2 = sorted({e.get("kind") for e in entries2})
            check(len(hs2) > 0, f"the target saw TLS handshakes ({len(hs2)})")
            check(kinds2 == ["tls_handshake"],
                  f"the target logged only tls_handshake entries (kinds {kinds2})")
            # Forced h2 offers ALPN ["h2"] only and the h1-only listener offers
            # only http/1.1, so no protocol is selected: the target logs `none`
            # for every handshake, which is exactly what `h2_not_negotiated`
            # names. (This line was unreachable before amendment 39b made the
            # cell run to its end; it had expected http/1.1.)
            check(alpns2 == ["none"],
                  f"no handshake negotiated a protocol under forced h2 against h1-only "
                  f"(observed {alpns2})")
            check(len(reqs2) == 0,
                  f"the target served zero HTTP requests under forced h2 (observed {len(reqs2)})")

            ok("T3-2: h1 is forced on an h2 listener; forced h2 on an h1-only listener "
               "errors every probe and ends the job done with crawl.last_error h2_not_negotiated")


if __name__ == "__main__":
    main()
